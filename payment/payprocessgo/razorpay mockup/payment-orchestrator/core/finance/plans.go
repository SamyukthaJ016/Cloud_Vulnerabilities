package finance

// Plan is a single purchasable SKU
type Plan struct {
	ID           string   // e.g. product_1_monthly
	ProductID    string   // e.g. product_1 | master
	ProductName  string   // e.g. "Product 1" — rename when real names arrive
	BillingCycle string   // monthly | yearly
	AmountPaise  int      // 0 until prices decided
	Currency     string   // INR only for now
	Role         string   // role granted on purchase: member | patron
	Features     []string // shown on plan card in UI
}

// AllPlans is the single source of truth for every SKU
// To rename a product: change ProductName only — ID stays stable
// To add a product: add 2 entries (monthly + yearly) here only
var AllPlans = []Plan{
	{
		ID:           "product_1_monthly",
		ProductID:    "product_1",
		ProductName:  "Product 1",
		BillingCycle: "monthly",
		AmountPaise:  100000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_1_yearly",
		ProductID:    "product_1",
		ProductName:  "Product 1",
		BillingCycle: "yearly",
		AmountPaise:  1000000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_2_monthly",
		ProductID:    "product_2",
		ProductName:  "Product 2",
		BillingCycle: "monthly",
		AmountPaise:  100000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_2_yearly",
		ProductID:    "product_2",
		ProductName:  "Product 2",
		BillingCycle: "yearly",
		AmountPaise:  1000000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_3_monthly",
		ProductID:    "product_3",
		ProductName:  "Product 3",
		BillingCycle: "monthly",
		AmountPaise:  100000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_3_yearly",
		ProductID:    "product_3",
		ProductName:  "Product 3",
		BillingCycle: "yearly",
		AmountPaise:  1000000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_4_monthly",
		ProductID:    "product_4",
		ProductName:  "Product 4",
		BillingCycle: "monthly",
		AmountPaise:  100000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_4_yearly",
		ProductID:    "product_4",
		ProductName:  "Product 4",
		BillingCycle: "yearly",
		AmountPaise:  1000000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_5_monthly",
		ProductID:    "product_5",
		ProductName:  "Product 5",
		BillingCycle: "monthly",
		AmountPaise:  100000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "product_5_yearly",
		ProductID:    "product_5",
		ProductName:  "Product 5",
		BillingCycle: "yearly",
		AmountPaise:  1000000,
		Currency:     "INR",
		Role:         "member",
		Features:     []string{},
	},
	{
		ID:           "master_monthly",
		ProductID:    "master",
		ProductName:  "Master Plan",
		BillingCycle: "monthly",
		AmountPaise:  450000,
		Currency:     "INR",
		Role:         "patron",
		Features:     []string{},
	},
	{
		ID:           "master_yearly",
		ProductID:    "master",
		ProductName:  "Master Plan",
		BillingCycle: "yearly",
		AmountPaise:  2900000,
		Currency:     "INR",
		Role:         "patron",
		Features:     []string{},
	},
}

// GetPlanByID returns a plan or nil — used by /subscribe to prevent spoofing
func GetPlanByID(id string) *Plan {
	for _, p := range AllPlans {
		if p.ID == id {
			return &p
		}
	}
	return nil
}

// GetPlansByProduct returns both cycles for a product
func GetPlansByProduct(productID string) []Plan {
	result := []Plan{}
	for _, p := range AllPlans {
		if p.ProductID == productID {
			result = append(result, p)
		}
	}
	return result
}
