package core
import( 
	"net/http"
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)
type TrafficLog struct{
	ID		primitive.ObjectID `bson:"_id,omitempty"`
	CreatedAt  time.Time      `bson:"created_at"`
	Method	  string	   `bson:"method"`
	URL       string     `bson:"url"`
	Host	  string     `bson:"host"`
	Path	  string     `bson:"path"`
	ReqHeaders http.Header `bson:"req_headers"`
	ReqBody   string	 `bson:"req_body"`
	RespStatus string	 `bson:"resp_status"`
	RespBody  string	 `bson:"resp_body"`
	Analyzed   bool       `bson:"analyzed"`
	IsScanned  bool       `bson:"is_scanned"`
	Tags	   []string   `bson:"tags"`
}