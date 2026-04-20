package entitlement

// Role constants — single source of truth
// Never compare role strings directly anywhere else in the codebase
const (
	RoleFree   = "free"
	RoleMember = "member"
	RolePatron = "patron"
)

// ProductIDs — all known products
// master is not a product — it is a bundle that grants patron role
var KnownProducts = []string{
	"product_1",
	"product_2",
	"product_3",
	"product_4",
	"product_5",
}

// HasAccess is the single place that decides if a user can use a product
// Call this from /verify — never replicate this logic in handlers
//
// Rules:
//   patron  → access to everything, always
//   member  → access only if activeProductID matches requested product
//   free    → no access to anything
func HasAccess(role string, activeProductID string, requestedProduct string) bool {
	switch role {
	case RolePatron:
		return true
	case RoleMember:
		return activeProductID == requestedProduct
	default:
		return false
	}
}

// RoleForPlan returns the role a plan grants
// patron only comes from master plan
// everything else is member
func RoleForPlan(productID string) string {
	if productID == "master" {
		return RolePatron
	}
	return RoleMember
}

// IsValidRole checks if a role string is one we recognize
func IsValidRole(role string) bool {
	switch role {
	case RoleFree, RoleMember, RolePatron:
		return true
	default:
		return false
	}
}

// IsValidProduct checks if a product ID is one we recognize
func IsValidProduct(productID string) bool {
	for _, p := range KnownProducts {
		if p == productID {
			return true
		}
	}
	// master is valid for subscribe but not for per-product access check
	return productID == "master"
}
