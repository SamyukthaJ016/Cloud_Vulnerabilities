#!/bin/bash
# Cleanup script for CloudGuard CloudFormation resources

echo "🧹 Cleaning up existing CloudGuard CloudFormation resources..."
echo ""

# Delete all CloudGuard stacks
echo "📋 Finding all CloudGuard stacks..."
STACKS=$(aws cloudformation list-stacks \
    --stack-status-filter CREATE_COMPLETE CREATE_FAILED ROLLBACK_COMPLETE UPDATE_COMPLETE \
    --query 'StackSummaries[?contains(StackName, `CloudGuard`)].StackName' \
    --output text)

if [ -z "$STACKS" ]; then
    echo "✅ No CloudGuard stacks found"
else
    echo "Found stacks: $STACKS"
    echo ""
    for stack in $STACKS; do
        echo "🗑️  Deleting stack: $stack"
        aws cloudformation delete-stack --stack-name "$stack"
    done
    
    echo ""
    echo "⏳ Waiting for stacks to be deleted..."
    for stack in $STACKS; do
        aws cloudformation wait stack-delete-complete --stack-name "$stack" 2>/dev/null || true
    done
fi

# Delete orphaned IAM roles
echo ""
echo "🔍 Finding orphaned CloudGuard IAM roles..."
ROLES=$(aws iam list-roles \
    --query 'Roles[?contains(RoleName, `CloudGuard`)].RoleName' \
    --output text)

if [ -z "$ROLES" ]; then
    echo "✅ No orphaned roles found"
else
    echo "Found roles: $ROLES"
    for role in $ROLES; do
        echo "🗑️  Deleting role: $role"
        # Detach managed policies first
        POLICIES=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text)
        for policy in $POLICIES; do
            aws iam detach-role-policy --role-name "$role" --policy-arn "$policy"
        done
        # Delete the role
        aws iam delete-role --role-name "$role" 2>/dev/null || true
    done
fi

# Delete orphaned IAM policies
echo ""
echo "🔍 Finding orphaned CloudGuard IAM policies..."
POLICIES=$(aws iam list-policies --scope Local \
    --query 'Policies[?contains(PolicyName, `CloudGuard`)].{Name:PolicyName,Arn:Arn}' \
    --output text)

if [ -z "$POLICIES" ]; then
    echo "✅ No orphaned policies found"
else
    echo "Found policies:"
    echo "$POLICIES" | while read name arn; do
        echo "🗑️  Deleting policy: $name"
        # Delete all policy versions except default
        VERSIONS=$(aws iam list-policy-versions --policy-arn "$arn" \
            --query 'Versions[?IsDefaultVersion==`false`].VersionId' \
            --output text)
        for version in $VERSIONS; do
            aws iam delete-policy-version --policy-arn "$arn" --version-id "$version" 2>/dev/null || true
        done
        # Delete the policy
        aws iam delete-policy --policy-arn "$arn" 2>/dev/null || true
    done
fi

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "💡 You can now create a new CloudFormation stack without conflicts"
