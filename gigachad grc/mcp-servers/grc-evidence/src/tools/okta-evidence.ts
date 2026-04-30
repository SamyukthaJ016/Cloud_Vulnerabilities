import axios, { AxiosInstance } from 'axios';

interface OktaEvidenceParams {
  domain: string;
  checks?: string[];
}

interface EvidenceResult {
  service: string;
  collectedAt: string;
  domain: string;
  findings: unknown[];
  summary: {
    totalUsers: number;
    compliantUsers: number;
    nonCompliantUsers: number;
  };
}

export async function collectOktaEvidence(params: OktaEvidenceParams): Promise<EvidenceResult> {
  const {
    domain,
    checks = ['mfa-status', 'password-policy', 'app-assignments', 'inactive-users'],
  } = params;

  const apiToken = process.env.OKTA_API_TOKEN;
  if (!apiToken) {
    return {
      service: 'okta',
      collectedAt: new Date().toISOString(),
      domain,
      findings: [{ error: 'OKTA_API_TOKEN environment variable not set' }],
      summary: {
        totalUsers: 0,
        compliantUsers: 0,
        nonCompliantUsers: 0,
      },
    };
  }

  const client = axios.create({
    baseURL: `https://${domain}/api/v1`,
    headers: {
      Authorization: `SSWS ${apiToken}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
  });

  const findings: unknown[] = [];
  let compliantCount = 0;
  let nonCompliantCount = 0;
  let totalUsers = 0;

  try {
    // Check password policy
    if (checks.includes('password-policy')) {
      const policyFindings = await collectPasswordPolicies(client);
      findings.push(policyFindings);
    }

    // Get users and check MFA
    if (checks.includes('mfa-status') || checks.includes('inactive-users')) {
      const userFindings = await collectUserEvidence(client, checks);
      findings.push(userFindings);
      
      totalUsers = userFindings.totalUsers;
      compliantCount = userFindings.compliantUsers;
      nonCompliantCount = userFindings.nonCompliantUsers;
    }

    // Check app assignments
    if (checks.includes('app-assignments')) {
      const appFindings = await collectAppAssignments(client);
      findings.push(appFindings);
    }

    // Get organization security settings
    const orgSettings = await collectOrgSettings(client);
    findings.push(orgSettings);

    // Get authentication policies
    const authPolicies = await collectAuthenticationPolicies(client);
    findings.push(authPolicies);

    return {
      service: 'okta',
      collectedAt: new Date().toISOString(),
      domain,
      findings,
      summary: {
        totalUsers,
        compliantUsers: compliantCount,
        nonCompliantUsers: nonCompliantCount,
      },
    };
  } catch (error) {
    return {
      service: 'okta',
      collectedAt: new Date().toISOString(),
      domain,
      findings: [{ error: error instanceof Error ? error.message : 'Unknown error' }],
      summary: {
        totalUsers: 0,
        compliantUsers: 0,
        nonCompliantUsers: 0,
      },
    };
  }
}

async function collectPasswordPolicies(client: AxiosInstance): Promise<unknown> {
  try {
    const { data: policies } = await client.get('/policies', {
      params: { type: 'PASSWORD' },
    });

    const policyDetails = await Promise.all(
      policies.map(async (policy: { id: string; name: string; status: string }) => {
        try {
          const { data: rules } = await client.get(`/policies/${policy.id}/rules`);
          return {
            id: policy.id,
            name: policy.name,
            status: policy.status,
            rules: rules.map((rule: Record<string, unknown>) => ({
              name: rule.name,
              status: rule.status,
              conditions: rule.conditions,
              actions: rule.actions,
            })),
          };
        } catch {
          return {
            id: policy.id,
            name: policy.name,
            status: policy.status,
            rules: [],
          };
        }
      })
    );

    // Analyze password policies for compliance
    const compliance = {
      hasMinLength: false,
      minLengthValue: 0,
      requiresComplexity: false,
      hasExpirationPolicy: false,
      hasLockoutPolicy: false,
    };

    for (const policy of policyDetails) {
      for (const rule of policy.rules) {
        const actions = rule.actions as Record<string, unknown>;
        const passwordComplexity = actions?.passwordChange as Record<string, unknown>;
        
        if (passwordComplexity) {
          const minLength = passwordComplexity.minLength as number;
          if (minLength && minLength >= 8) {
            compliance.hasMinLength = true;
            compliance.minLengthValue = Math.max(compliance.minLengthValue, minLength);
          }
          
          const complexity = passwordComplexity.complexity as Record<string, number>;
          if (complexity) {
            compliance.requiresComplexity =
              compliance.requiresComplexity ||
              ((complexity.minLowerCase ?? 0) > 0 &&
                (complexity.minUpperCase ?? 0) > 0 &&
                (complexity.minNumber ?? 0) > 0);
          }
        }
      }
    }

    return {
      type: 'password_policies',
      count: policies.length,
      policies: policyDetails,
      compliance,
    };
  } catch (error) {
    return {
      type: 'password_policies',
      error: error instanceof Error ? error.message : 'Failed to fetch password policies',
    };
  }
}

async function collectUserEvidence(
  client: AxiosInstance,
  checks: string[]
): Promise<{
  type: string;
  totalUsers: number;
  compliantUsers: number;
  nonCompliantUsers: number;
  users: unknown[];
}> {
  try {
    const users: unknown[] = [];
    let compliantUsers = 0;
    let nonCompliantUsers = 0;

    // Get all users (paginated)
    let url = '/users?limit=200';
    while (url) {
      const response = await client.get(url);
      const userData = response.data;

      for (const user of userData) {
        const userInfo: Record<string, unknown> = {
          id: user.id,
          status: user.status,
          email: user.profile?.email,
          firstName: user.profile?.firstName,
          lastName: user.profile?.lastName,
          created: user.created,
          lastLogin: user.lastLogin,
          lastUpdated: user.lastUpdated,
        };

        let isCompliant = true;

        // Check MFA status
        if (checks.includes('mfa-status')) {
          try {
            const { data: factors } = await client.get(`/users/${user.id}/factors`);
            const enrolledFactors = factors.filter(
              (f: { status: string }) => f.status === 'ACTIVE'
            );
            userInfo.mfa = {
              enrolled: enrolledFactors.length > 0,
              factors: enrolledFactors.map((f: { factorType: string; provider: string }) => ({
                type: f.factorType,
                provider: f.provider,
              })),
            };

            if (enrolledFactors.length === 0) {
              isCompliant = false;
            }
          } catch {
            userInfo.mfa = { error: 'Could not fetch MFA status' };
          }
        }

        // Check for inactive users
        if (checks.includes('inactive-users')) {
          const lastLogin = user.lastLogin ? new Date(user.lastLogin) : null;
          const daysSinceLogin = lastLogin
            ? Math.floor((Date.now() - lastLogin.getTime()) / (1000 * 60 * 60 * 24))
            : null;

          userInfo.inactivity = {
            lastLogin: user.lastLogin,
            daysSinceLogin,
            isInactive: daysSinceLogin === null || daysSinceLogin > 90,
          };

          if (daysSinceLogin === null || daysSinceLogin > 90) {
            isCompliant = false;
          }
        }

        userInfo.isCompliant = isCompliant;
        users.push(userInfo);

        if (isCompliant) {
          compliantUsers++;
        } else {
          nonCompliantUsers++;
        }
      }

      // Check for pagination
      const linkHeader = response.headers.link;
      if (linkHeader) {
        const nextLink = linkHeader.split(',').find((l: string) => l.includes('rel="next"'));
        if (nextLink) {
          const match = nextLink.match(/<([^>]+)>/);
          url = match ? match[1].replace(`https://${client.defaults.baseURL}`, '') : '';
        } else {
          url = '';
        }
      } else {
        url = '';
      }
    }

    return {
      type: 'users',
      totalUsers: users.length,
      compliantUsers,
      nonCompliantUsers,
      users,
    };
  } catch (error) {
    return {
      type: 'users',
      totalUsers: 0,
      compliantUsers: 0,
      nonCompliantUsers: 0,
      users: [{ error: error instanceof Error ? error.message : 'Failed to fetch users' }],
    };
  }
}

async function collectAppAssignments(client: AxiosInstance): Promise<unknown> {
  try {
    const { data: apps } = await client.get('/apps?limit=200');

    const appDetails = await Promise.all(
      apps.map(async (app: { id: string; name: string; label: string; status: string; signOnMode: string }) => {
        try {
          const { data: users } = await client.get(`/apps/${app.id}/users?limit=200`);
          const { data: groups } = await client.get(`/apps/${app.id}/groups?limit=200`);

          return {
            id: app.id,
            name: app.name,
            label: app.label,
            status: app.status,
            signOnMode: app.signOnMode,
            assignedUsers: users.length,
            assignedGroups: groups.length,
          };
        } catch {
          return {
            id: app.id,
            name: app.name,
            label: app.label,
            status: app.status,
            assignedUsers: 'N/A',
            assignedGroups: 'N/A',
          };
        }
      })
    );

    return {
      type: 'applications',
      count: apps.length,
      applications: appDetails,
      compliance: {
        activeApps: appDetails.filter((a) => a.status === 'ACTIVE').length,
        inactiveApps: appDetails.filter((a) => a.status !== 'ACTIVE').length,
      },
    };
  } catch (error) {
    return {
      type: 'applications',
      error: error instanceof Error ? error.message : 'Failed to fetch applications',
    };
  }
}

async function collectOrgSettings(client: AxiosInstance): Promise<unknown> {
  try {
    const { data: org } = await client.get('/org');

    return {
      type: 'organization_settings',
      companyName: org.companyName,
      website: org.website,
      status: org.status,
      subdomain: org.subdomain,
      created: org.created,
      lastUpdated: org.lastUpdated,
      settings: org.settings,
    };
  } catch (error) {
    return {
      type: 'organization_settings',
      error: error instanceof Error ? error.message : 'Failed to fetch org settings',
    };
  }
}

async function collectAuthenticationPolicies(client: AxiosInstance): Promise<unknown> {
  try {
    const { data: policies } = await client.get('/policies', {
      params: { type: 'OKTA_SIGN_ON' },
    });

    const policyDetails = await Promise.all(
      policies.map(async (policy: { id: string; name: string; status: string; priority: number }) => {
        try {
          const { data: rules } = await client.get(`/policies/${policy.id}/rules`);
          return {
            id: policy.id,
            name: policy.name,
            status: policy.status,
            priority: policy.priority,
            rules: rules.map((rule: Record<string, unknown>) => ({
              name: rule.name,
              status: rule.status,
              priority: rule.priority,
            })),
          };
        } catch {
          return {
            id: policy.id,
            name: policy.name,
            status: policy.status,
            rules: [],
          };
        }
      })
    );

    return {
      type: 'authentication_policies',
      count: policies.length,
      policies: policyDetails,
    };
  } catch (error) {
    return {
      type: 'authentication_policies',
      error: error instanceof Error ? error.message : 'Failed to fetch auth policies',
    };
  }
}

