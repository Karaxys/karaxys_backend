package pii
import(
	"math"
	"math/big"
	"strings"
	"unicode"
)

func LuhnCheck(number string) bool {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, number)

	if len(clean) < 2 {
		return false
	}

	sum := 0
	isSecond := false

	for i := len(clean) - 1; i >= 0; i-- {
		d := int(clean[i] - '0')
		if isSecond {
			d = d * 2
		}
		sum += d / 10
		sum += d % 10
		isSecond = !isSecond
	}

	return sum%10 == 0
}

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

var verhoeffInv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

func VerhoeffCheck(number string) bool{
	clean := strings.Map(func(r rune) rune{
		if unicode.IsDigit(r){
			return r
		}
		return -1
	}, number)
	if len(clean) != 12{
		return false
	}
	c := 0
	length := len(clean)
	for i := 0; i < length; i++ {
		val := int(clean[length-1-i] - '0')
		pVal := verhoeffP[i%8][val]
		c = verhoeffD[c][pVal]
	}

	return c == 0
}

func IBANCheck(iban string) bool {
	iban = strings.ToUpper(strings.ReplaceAll(iban, " ", ""))
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	var numericString strings.Builder
	for _, ch := range rearranged {
		if ch >= '0' && ch <= '9' {
			numericString.WriteRune(ch)
		} else if ch >= 'A' && ch <= 'Z' {
			val := int(ch) - 55
			numericString.WriteString(strconv(val))
		} else {
			return false
		}
	}
	bigInt := new(big.Int)
	bigInt, success := bigInt.SetString(numericString.String(), 10)
	if !success {
		return false
	}
	remainder := new(big.Int).Mod(bigInt, big.NewInt(97))
	
	return remainder.Int64() == 1
}

func strconv(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return big.NewInt(int64(i)).String()
}

func ShannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}	
	charCounts := make(map[rune]float64)
	for _, ch := range data {
		charCounts[ch]++
	}
	var entropy float64
	totalChars := float64(len(data))
	for _, count := range charCounts {
		p := count / totalChars
		entropy += -p * math.Log2(p)
	}
	return entropy
}