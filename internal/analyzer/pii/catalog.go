package pii

import(
	"regexp"
)

type PIIRule struct {
	Name     string
	Regex    *regexp.Regexp
	Keywords []string
	Verifier func(string) bool
}

var(
	regEmail        = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	regPhone        = regexp.MustCompile(`(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`)
	regDate         = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	regVisa         = regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)
	regMasterCard   = regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)
	regCardGeneric  = regexp.MustCompile(`\b\d{13,19}\b`)
	regIBAN         = regexp.MustCompile(`[a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}`)
	regSWIFT        = regexp.MustCompile(`\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`)
	regUUID         = regexp.MustCompile(`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
	regPAN          = regexp.MustCompile(`[A-Z]{5}[0-9]{4}[A-Z]{1}`)
	regAadhar       = regexp.MustCompile(`^\d{4}\s\d{4}\s\d{4}$`)
	regSSN          = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	regPassport     = regexp.MustCompile(`[A-Z]{1}[0-9]{7}`)
	regDriverLic    = regexp.MustCompile(`(?i)[a-z0-9]{6,12}`)
	regCanadianSIN  = regexp.MustCompile(`\d{3}-\d{3}-\d{3}`)
	regFinnishPIN   = regexp.MustCompile(`\d{6}[+-A]\d{3}[0-9A-Z]`)
	regBearer       = regexp.MustCompile(`(?i)Bearer\s[a-zA-Z0-9\-\._~\+\/]+=*`)
	regJWT          = regexp.MustCompile(`\beyJ[a-zA-Z0-9\-\._~\+\/]{20,}\b`)
	regAWS          = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	regGenericString = regexp.MustCompile(`.{3,}`) 
	regGenericInt    = regexp.MustCompile(`\b\d+\b`)
)

var Rules = []PIIRule{
	{
		Name:     "VISA_CARD",
		Regex:    regVisa,
		Keywords: []string{"cardNum","cardnum", "card_number", "card", "cc", "visa", "payment", "billing", "credit", "debit"},
		Verifier: LuhnCheck,
	},
	{
		Name:     "MASTER_CARD",
		Regex:    regMasterCard,
		Keywords: []string{"cardNum","cardnum", "card_number", "card", "cc", "master", "payment", "billing", "credit", "debit"},
		Verifier: LuhnCheck,
	},
	{
		Name:     "CREDIT_CARD",
		Regex:    regCardGeneric,
		Keywords: []string{"cardNum","cardnum", "card_number", "credit_card", "debit_card", "cc_num", "payment", "billing", "credit", "debit"},
		Verifier: nil,
	},
	{
		Name:     "IBAN_CODE",
		Regex:    regIBAN,
		Keywords: []string{"iban", "bank", "account"},
		Verifier: IBANCheck, 
	},
	{
		Name:     "SWIFT_CODE",
		Regex:    regSWIFT,
		Keywords: []string{"swift", "bic", "bank"},
		Verifier: nil,
	},
	{
		Name:     "INDIAN_PAN",
		Regex:    regPAN,
		Keywords: []string{"pan", "tax", "id"},
		Verifier: nil,
	},
	{
		Name:     "INDIAN_AADHAR",
		Regex:    regAadhar,
		Keywords: []string{"aadhar", "uidai", "id"},
		Verifier: VerhoeffCheck,
	},
	{
		Name:     "INDIAN_HEALTH_ID",
		Regex:    regexp.MustCompile(`\d{2}-\d{4}-\d{4}-\d{4}`),
		Keywords: []string{"health", "abha", "ndhm"},
		Verifier: nil,
	},
	{
		Name:     "US_SSN",
		Regex:    regSSN,
		Keywords: []string{"ssn", "social", "tax"},
		Verifier: nil,
	},
	{
		Name:     "US_MEDICARE",
		Regex:    regexp.MustCompile(`[1-9][A-Z][0-9][A-Z][0-9][A-Z][0-9]{4}`),
		Keywords: []string{"medicare", "mbi", "insurance"},
		Verifier: nil,
	},
	{
		Name:     "CANADIAN_SIN",
		Regex:    regCanadianSIN,
		Keywords: []string{"sin", "social", "insurance"},
		Verifier: LuhnCheck,
	},
	{
		Name:     "STREET_ADDRESS",
		Regex:    regexp.MustCompile(`\b\d+\s[A-Z][a-z]+\s(St|Ave|Rd|Blvd|Lane|Drive|Way)\b`),
		Keywords: []string{"address", "street", "city", "zip", "billing", "shipping", "residence", "location", "streetAddress", "StreetAddress", "street_address", "Street_Address", "zipCode", "zip_code", "zipcode", "ZipCode"},
		Verifier: nil,
	},
	{
		Name:     "FINNISH_PIN",
		Regex:    regFinnishPIN,
		Keywords: []string{"pin", "hetu", "id"},
		Verifier: nil,
	},
	{
		Name:     "GERMAN_INSURANCE_ID",
		Regex:    regexp.MustCompile(`[A-Z]\d{9}`),
		Keywords: []string{"insurance", "kvnr"},
		Verifier: nil,
	},
	{
		Name:     "PASSPORT_NO",
		Regex:    regPassport,
		Keywords: []string{"passport", "travel", "document"},
		Verifier: nil,
	},
	{
		Name:     "DRIVERS_LICENSE",
		Regex:    regDriverLic,
		Keywords: []string{"driver", "license", "dl", "permit"},
		Verifier: nil,
	},
	{
		Name:     "EMAIL",
		Regex:    regEmail,
		Keywords: nil,
		Verifier: nil,
	},
	{
		Name:     "PHONE_NUMBER",
		Regex:    regPhone,
		Keywords: []string{"phone", "mobile", "contact", "fax", "tel", "cell"},
		Verifier: nil,
	},
	{
		Name:     "DATE_OF_BIRTH",
		Regex:    regDate,
		Keywords: []string{"dob", "birth", "date"},
		Verifier: nil,
	},
	{
		Name:     "PASSWORD",
		Regex:    regGenericString,
		Keywords: []string{"password", "passwd", "pwd", "secret", "pass"},
		Verifier: nil,
	},
	{
		Name:     "FULL_NAME",
		Regex:    regexp.MustCompile(`[A-Z][a-z]+\s[A-Z][a-z]+`),
		Keywords: []string{"name", "fullname", "customer", "user", "answer", "fullName", "full_name", "Name"},
		Verifier: nil,
	},
	{
		Name:     "AUTH_TOKEN_BEARER",
		Regex:    regBearer,
		Keywords: []string{"authorization", "auth", "token"},
		Verifier: nil,
	},
	{
		Name:	 "JWT_TOKEN",
		Regex:    regJWT,
		Keywords: []string{"authentication", "token", "access_token", "access token", "refresh_token", "refresh token", "jwt", "id_token", "id token", "auth"},
		Verifier: nil,
	},
	{
		Name:     "AWS_KEY",
		Regex:    regAWS,
		Keywords: []string{"aws", "amazon", "access_key", "access key", "secret_key","aws_access_key_id","aws_access_key","access_key","access_key_id","aws_key","aws_id"},
		Verifier: nil,
	},
	{
		Name:     "USER_ID",
		Regex:    regGenericInt,
		Keywords: []string{"user_id", "userid", "uid", "account_id", "member_id"},
		Verifier: nil,
	},
	{
		Name:     "USERNAME",
		Regex:    regGenericString,
		Keywords: []string{"username", "user_name", "login", "handle", "userName"},
		Verifier: nil,
	},
	{
		Name:     "ADDRESS",
		Regex:    regexp.MustCompile(`\b\d+\s[a-zA-Z]+\s[a-zA-Z]+`), 
		Keywords: []string{"address", "street", "city", "zip", "billing", "shipping", "residence", "location", "streetAddress", "StreetAddress", "street_address", "Street_Address"},
		Verifier: nil,
	},
	{
		Name:     "PERSON_NAME",
		Regex:    regexp.MustCompile(`[a-zA-Z\s]{3,}`),
		Keywords: []string{"fullname", "full_name", "customer_name", "fullName", "name"},
		Verifier: nil,
	},
}