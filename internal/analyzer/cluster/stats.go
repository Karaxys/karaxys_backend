package cluster

import(
	"regexp"
	"strconv"
)

var(
	regexUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	regexHash = regexp.MustCompile(`^[a-f0-9]{32,}$`)
)

func ClassifySegment(segment string) (isParam bool, paramName string){
	if _, err := strconv.Atoi(segment); err == nil{
		return true, "{id}"
	}
	if regexUUID.MatchString(segment){
		return true, "{uuid}"
	}
	if regexHash.MatchString(segment){
		return true, "{token}"
	}

	return false, ""
}