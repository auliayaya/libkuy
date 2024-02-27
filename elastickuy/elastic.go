package elastickuy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	elastic "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"log"
	"net/http"
	"openlib/env"
	"openlib/logger"
	"reflect"
	"time"
)

type RequestElastic struct {
	Index      string
	Body       interface{}
	DocumentID string
	Ctx        context.Context
}
type ResponseElastic struct {
	Code    int
	Message string
	Body    interface{}
}
type ElasticAbstract interface {
	Store(request RequestElastic) (response bool, statusCode int, err error)
	Update(request RequestElastic) (response bool, err error)
	Search(request RequestElastic) (total float64, response interface{}, err error)
	Delete(request RequestElastic) (response bool, err error)
}

var _ ElasticAbstract = ElasticMaster{}

type ElasticMaster struct {
	Client    *elastic.Client
	timeout   time.Duration
	zapLogger logger.Logger
}

func NewElasticMaster(env env.Env, zapLogger logger.Logger) ElasticMaster {
	url := env.DBEHost
	username := env.DBEUsername
	password := env.DBEPassword

	cfg := elastic.Config{
		Addresses: []string{
			url,
		},
		Username: username,
		Password: password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
		},
	}

	client, _ := elastic.NewClient(cfg)
	_, err := client.Info()
	if err != nil {
		zapLogger.Zap.Info("Url: ", url)
		zapLogger.Zap.Panic(err)
		zapLogger.Zap.Info("ElasticMaster Connection Refused")
	}

	zapLogger.Zap.Info("ElasticMaster Connection Established")
	return ElasticMaster{
		Client:  client,
		timeout: time.Second * 10,
	}
}

func (e ElasticMaster) Store(request RequestElastic) (response bool, statusCode int, err error) {
	fmt.Println(" ElasticMaster || request =>", request)
	body, err := json.Marshal(request.Body)
	if err != nil {
		e.zapLogger.Zap.Error(err)
		return false, statusCode, err
	}

	req := esapi.CreateRequest{
		Index:      request.Index,
		DocumentID: request.DocumentID,
		Body:       bytes.NewReader(body),
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	res, err := req.Do(ctx, e.Client)

	if err != nil {
		fmt.Println("error", reflect.TypeOf(err))
		// e.zapLogger.Zap.Error(err)
		return false, statusCode, err
	}

	errExeeded := fmt.Sprint(err)
	if errExeeded == "context.deadlineExceededError" {
		fmt.Println("error", err)
		// e.zapLogger.Zap.Error(err)
		return false, statusCode, err
	}
	defer res.Body.Close()

	var resBody map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		log.Printf("Error parsing the response body: %s", err)
	} else {
		fmt.Println("resBody", resBody)
		fmt.Println("RES", res.String())
		fmt.Println("RES CODE", res.StatusCode)
		// e.zapLogger.Zap.Info("RES", res)
		// e.zapLogger.Zap.Info("res.String()=>", res.String())
		if res.IsError() {
			fmt.Println("resBody[error]", resBody["error"])
			// 	if len(resBody) != 0 {
			// 		log.Printf("[%s] %s: %s",
			// 			res.Status(),
			// 			resBody["error"].(map[string]interface{})["type"],
			// 			resBody["error"].(map[string]interface{})["reason"].(string),
			// 		)
			// 		fmt.Println("IsError=> ", resBody["error"])
			// 		if resBody["error"].(map[string]interface{})["reason"] != nil {
			// 			reason = resBody["error"].(map[string]interface{})["reason"].(string)
			// 		}
			// 	}
			// 	return false, reason, err
		}
	}
	return true, res.StatusCode, err
}

func (e ElasticMaster) Update(request RequestElastic) (response bool, err error) {
	//fmt.Println(" ElasticMaster || request =>", request)
	body, err := json.Marshal(request.Body)
	if err != nil {
		// e.zapLogger.Zap.Error(err)
	}

	req := esapi.UpdateRequest{
		Index:      request.Index,
		DocumentID: request.DocumentID,
		Body:       bytes.NewReader(body),
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	res, err := req.Do(ctx, e.Client)
	if err != nil {
		// e.zapLogger.Zap.Error(err)
		return false, err
	}
	defer res.Body.Close()

	if res.IsError() {
		// e.zapLogger.Zap.Error(res.String())
		return false, err
	}

	return true, err
}

func (e ElasticMaster) Search(request RequestElastic) (total float64, response interface{}, err error) {
	//fmt.Println(" ElasticMaster || request =>", request)
	var buf bytes.Buffer
	// query := map[string]interface{}{
	// 	"query": map[string]interface{}{
	// 		"match_all": map[string]interface{}{
	// 			// "name": "SHM",
	// 			// "status":        "Open",
	// 		},
	// 	},
	// }
	// query, err := json.Marshal(data)
	// if err != nil {
	// 	e.zapLogger.Zap.Error(err)
	// 	return response, err
	// }

	if err := json.NewEncoder(&buf).Encode(request.Body); err != nil {
		// e.zapLogger.Zap.Error(err)
		return total, response, err
	}

	res, err := e.Client.Search(
		e.Client.Search.WithContext(request.Ctx),
		e.Client.Search.WithIndex(request.Index),
		e.Client.Search.WithBody(&buf),
		e.Client.Search.WithTrackTotalHits(true),
		e.Client.Search.WithPretty(),
	)

	if err != nil {
		// e.zapLogger.Zap.Error(err)
		return total, response, err
	}

	defer res.Body.Close()

	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			log.Printf("Error parsing the response body: %s", err)
		} else {
			log.Printf("[%s] %s: %s",
				res.Status(),
				e["error"].(map[string]interface{})["type"],
				e["error"].(map[string]interface{})["reason"],
			)
		}
	}
	var dataTrx map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&dataTrx); err != nil {
		log.Printf("Error parsing the response body: %s", err)
		return total, response, err
	}

	// Print the response status, number of results, and request duration.
	// e.zapLogger.Zap.Info("Data is empty!!")
	totalData := dataTrx["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)
	log.Printf(
		"[%s] %d hits; took: %dms",
		res.Status(),
		int(dataTrx["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)),
		int(dataTrx["took"].(float64)),
	)
	total = dataTrx["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)
	log.Println(int(total))
	if total == 0 {
		return total, response, err
	}
	data := dataTrx["hits"].(map[string]interface{})["hits"].([]interface{})
	return totalData, data, err
}

func (e ElasticMaster) Delete(request RequestElastic) (response bool, err error) {
	//fmt.Println(" ElasticMaster || request =>", request)
	reqDelete := esapi.DeleteRequest{
		Index:      request.Index,
		DocumentID: request.DocumentID,
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	resDelete, err := reqDelete.Do(ctx, e.Client)
	if err != nil {
		// e.zapLogger.Zap.Error(err)
		return false, err
	}
	defer resDelete.Body.Close()

	if resDelete.IsError() {
		// e.zapLogger.Zap.Error(err)
		return false, err
	}
	return true, err
}
