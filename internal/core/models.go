package core
import "net/http"

type TrafficLog struct{
	Method	  string	   `bson:"method"`
	URL       string     `bson:"url"`
	Host	  string     `bson:"host"`
	Path	  string     `bson:"path"`
	ReqHeaders http.Header `bson:"req_headers"`
	ReqBody   string	 `bson:"req_body"`
	RespStatus string	 `bson:"resp_status"`
	RespBody  string	 `bson:"resp_body"`
	Analyzed   bool       `bson:"analyzed"`
	Tags	   []string   `bson:"tags"`
}