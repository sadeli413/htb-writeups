package main

import (
    "fmt"
    "net/http"
    // "io/ioutil"
    "net/http/cookiejar"
    "reflect"
    "os"
)


func main() {
    // Define constants
    // username := "gopher"
    // password := "helloworld"
    // lhost := "10.10.14.30"
    // lport := "8888"

    // Create http client 
    jar, err := cookiejar.New(nil)
    check(err, "Could not create cookie jar")
    client := http.Client{Jar:jar}
    fmt.Println(reflect.TypeOf(client).String())
    os.Exit(1)

    // createUser(client, username, password)
    check(err, "Could not make request")
    // defer response.Body.Close()
    // body, err := ioutil.ReadAll(response.Body)
    // fmt.Println(string(body))
}

// func createUser(client, username, password string) {
// }

func postRequest(client http.Client, url string, data url.Values) (*http.Response) {
    response, err := http.PostForm(url, data)
    check(err, "Could not make post request")

}

func check(err error, message string) {
    if err != nil {
        fmt.Println(message)
        panic(err)
    }
}
