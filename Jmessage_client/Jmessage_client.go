package main

import (
	"bufio"
	"bytes"

	"hash/crc32"

	//"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	//"encoding/pem"

	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
	//"io/ioutil"
	//"log"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, body, err
	}

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("resp.Body failed", err.Error())
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, err
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer() ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, err
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption
	err = decryptMessages(result)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, err
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the server
func doReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage, err := encryptMessage([]byte(messageBody), username, pubkey)
	if err != nil {
		fmt.Println("encrypt failed", err)
		return err
	}

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) {
	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return err
	}

	return nil
}

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns MsgUrl
// and file hash, or an error.
func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, error) {
	// TODO: IMPLEMENT : EXCEPT FOR SENDING MESSAGE
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("random chachakey generation failed", err.Error())
		return "", err
	}
	plaintext, err := os.ReadFile(plaintextFilePath)
	if err != nil {
		fmt.Println("Read file failed", err.Error())
		return "", err
	}
	nonce := make([]byte, chacha20.NonceSize)
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		fmt.Println("chacha20 failed", err.Error())
		return "", err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	H := sha256.Sum256(ciphertext)
	ciphertextFilePath = getTempFilePath()
	err = os.WriteFile(ciphertextFilePath, ciphertext, 0777)
	if err != nil {
		fmt.Println("WriteFile failed", err.Error())
		return "", err
	}
	url, err := uploadFileToServer(ciphertextFilePath)
	if err != nil {
		fmt.Println("attachement upload failed", err.Error())
		return "", err
	}
	//send message MSGURL=<url>?KEY=<KEY>?H=<H>
	msgURL := "MSGURL=" + url + "?KEY=" + string(key) + "?H=" + hex.EncodeToString(H[:])
	return msgURL, nil
}

func decodePrivateSigningKey(privKey PrivKeyStruct) *ecdsa.PrivateKey {
	var result *ecdsa.PrivateKey

	// TODO: IMPLEMENT
	decSigSk, err := base64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		fmt.Println("base64 failed", err)
		return result
	}
	//fmt.Println(decSigSk)
	sigPKparse, err := x509.ParsePKCS8PrivateKey(decSigSk)
	if err != nil {
		fmt.Println("parse failed!", err)
		return result
	}
	result = sigPKparse.(*ecdsa.PrivateKey)
	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: IMPLEMENT:SOLVED
	sigSk := decodePrivateSigningKey(privKey)
	msgHash := sha256.Sum256(message)
	sign, err := ecdsa.SignASN1(rand.Reader, sigSk, msgHash[:])
	if err != nil {
		fmt.Println("sign failed", err)
		return nil
	}
	return sign
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	// TODO: IMPLEMENT
	//------verify Sig--------
	//toVerify = C1 + C2
	var ciphertext CiphertextStruct
	message, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("Error while base64 decoding payload", err)
		return nil, err
	}
	err = json.Unmarshal([]byte(message), &ciphertext)
	if err != nil {
		fmt.Println("Error while parsing JSON:", err)
		return nil, err
	}
	toVerify := ciphertext.C1 + ciphertext.C2
	// decode sigPK into ECDSA pk
	decsigPK, err := base64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
		fmt.Println("Error base64decode", err)
		return nil, err
	}
	sigPKparse, err := x509.ParsePKIXPublicKey(decsigPK)
	if err != nil {
		fmt.Println("sigPK parse failed", err)
		return nil, err
	}
	sigPK := sigPKparse.(*ecdsa.PublicKey)
	hashed := sha256.Sum256([]byte(toVerify))
	// verify sig
	sig, err := base64.StdEncoding.DecodeString(ciphertext.Sig)
	if err != nil {
		fmt.Println("Error base64", err)
		return nil, err
	}
	res := ecdsa.VerifyASN1(sigPK, hashed[:], sig)

	if !res {
		fmt.Println("sig verification failed")
		return nil, errors.New("sig verification failed")
	}
	// -------decrypt C1 to get K--------
	//decode C1
	decC1, err := base64.StdEncoding.DecodeString(ciphertext.C1)
	if err != nil {
		fmt.Println("Error when decoding C1", err)
		return nil, err
	}

	C1parse, err := x509.ParsePKIXPublicKey(decC1)
	if err != nil {
		fmt.Println("Parsing C1parse failed", err)
		return nil, err
	}

	//decode encSK

	decSK, err := base64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	if err != nil {
		fmt.Println("Decoding encSK failed", err)
		return nil, err
	}
	C1, err := C1parse.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		fmt.Println("C1 failed", err)
		return nil, err
	}
	encSK, err := x509.ParsePKCS8PrivateKey(decSK)
	if err != nil {
		fmt.Println("parse encSK failed", err)
		return nil, err
	}
	// compute K = SHA256(s * C1)
	EncSK, err := encSK.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		fmt.Println("EncSK failed", err)
		return nil, err
	}
	ssk, err := EncSK.ECDH(C1)
	if err != nil {
		fmt.Println("ssk failed", err)
		return nil, err
	}
	k := sha256.Sum256(ssk)

	//---decrypt C2 to plaintext---------
	//decode C2
	C2, err := base64.StdEncoding.DecodeString(ciphertext.C2)
	if err != nil {
		fmt.Println("Error when decoding C2", err)
		return nil, err
	}
	//decipher C2 with K
	cc, err := chacha20.NewUnauthenticatedCipher(k[:], make([]byte, chacha20.NonceSize))
	if err != nil {
		fmt.Println("Error when decoding chacha20", err)
		return nil, err
	}

	//parse M1 = username || 0x3A || M || CHECK
	M1 := make([]byte, len(C2))
	cc.XORKeyStream(M1, C2)

	parse1 := bytes.IndexByte(M1, 0x3A)

	username := M1[0:parse1]
	M := M1[parse1+1 : len(M1)-4]
	check := M1[len(M1)-4:]
	//compute CHECK' = CRC32(username || 0x3A || M )
	checksum := crc32.ChecksumIEEE(M1[0 : len(M1)-4])
	check1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(check1, checksum)
	if !bytes.Equal(check, check1) {
		fmt.Println("Checksum is not equal", err)
		return nil, err
	}
	//check username
	if !bytes.Equal(username, []byte(senderUsername)) {
		fmt.Println("username is not equal", err)
		return nil, err
	}
	return M, nil

}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
// sender public key
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) ([]byte, error) {
	// TODO: IMPLEMENT:SOLVED

	//-----C1&K-----------

	C1 := globalPubKey.EncPK
	decEncSK, err := base64.StdEncoding.DecodeString(globalPrivKey.EncSK)
	if err != nil {
		fmt.Println("decEncSK base64 failed", err)
		return nil, err
	}
	EncSK, err := x509.ParsePKCS8PrivateKey(decEncSK)
	if err != nil {
		fmt.Println("EncSK failed", err)
		return nil, err
	}
	encSK, err := EncSK.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		fmt.Println("encSK failed", err)
		return nil, err
	}
	decEncPK, err := base64.StdEncoding.DecodeString(pubkey.EncPK)
	if err != nil {
		fmt.Println("decEncPK failed", err)
		return nil, err
	}

	EncPK, err := x509.ParsePKIXPublicKey(decEncPK)
	if err != nil {
		fmt.Println("EncPK failed", err)
		return nil, err
	}

	encPK, err := EncPK.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		fmt.Println("encPK failed", err)
		return nil, err
	}

	ssk, err := encSK.ECDH(encPK)
	if err != nil {
		fmt.Println("ssk failed", err)
		return nil, err
	}

	k := sha256.Sum256(ssk)

	//--------C2------

	// M' = sender_username || 0x3A || M
	M1 := senderUsername + ":" + string(message)
	// CHECK = CRC32(M')
	check := crc32.ChecksumIEEE([]byte(M1))
	c := make([]byte, 4)
	binary.LittleEndian.PutUint32(c, check)
	// M'' = M' || CHECK.
	M2 := M1 + string(c)
	//chacha20 + base64
	nonce := make([]byte, chacha20.NonceSize)

	key, err := chacha20.NewUnauthenticatedCipher(k[:], nonce)

	if err != nil {
		fmt.Println("chacha20 failed", err)
		return nil, err
	}
	ciphertext := make([]byte, len(M2))
	key.XORKeyStream(ciphertext, []byte(M2))
	C2 := base64.StdEncoding.EncodeToString(ciphertext)

	//----------Sig-------
	//form string
	toSign := C1 + C2
	//decode private sigSK
	sigSK := decodePrivateSigningKey(globalPrivKey)
	hash := sha256.Sum256([]byte(toSign))
	sign, err := ecdsa.SignASN1(rand.Reader, sigSK, hash[:])
	if err != nil {
		fmt.Println("sign failed", err)
		return nil, err
	}
	Sig := base64.StdEncoding.EncodeToString(sign)

	cipherS := CiphertextStruct{C1, C2, Sig}

	ret, err := json.Marshal(cipherS)

	return ret, err
}

// send read recipt
// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) error {

	for i, m := range messageArray {
		if messageArray[i].ReceiptID != 0 {
			continue
		}
		getP, err := getPublicKeyFromServer(m.From)
		if err != nil {
			return err
		}
		getM, err := decryptMessage(m.Payload, m.From, getP, &globalPrivKey)
		if err != nil {
			fmt.Println("decrypt message failed")
			return err
		}

		messageArray[i].decrypted = string(getM)

		if string(getM[:6]) == "MSGURL" {
			// parse1 := strings.Index(string(getM), "?KEY=")
			// messageArray[i].url = string(getM[7:parse1])
			messageArray[i].url = string(getM[7:])
		}

		err = sendMessageToServer(m.To, m.From, []byte(""), 1)
		if err != nil {
			return err
		}
	}
	return nil
}
func saveDecryptedAttachment(data string, targetPath string) error {
	targetFile, err := os.Create(targetPath)
	if err != nil {
		fmt.Println("Create New Attachment File Failed", err.Error())
		return err
	}
	_, err = targetFile.Write([]byte(data))
	if err != nil {
		fmt.Println("Write Attachment failed", err.Error())
		return err
	}
	err = targetFile.Close()
	if err != nil {
		fmt.Println("Close File Failed", err.Error())
		return err
	}
	return err
}

// decryptAttachment
func decryptAttachemt(message MessageStruct, localpath string, targetPath string) (string, error) {
	var plaintext []byte
	if message.url != "" {
		url := message.url
		parse1 := strings.Index(string(url), "?KEY=")
		parse2 := strings.Index(string(url), "?H=")
		key := url[parse1+5 : parse2]
		hash := url[parse2+3:]

		ciphertext, err := os.ReadFile(localpath)
		if err != nil {
			fmt.Println("Error while reading downloaded file")
			return "", err
		}
		H := sha256.Sum256(ciphertext)
		if hash != hex.EncodeToString(H[:]) {
			fmt.Println("Error when verifying hash")
			return "", errors.New("Error when verifying hash")
		}

		cc, err := chacha20.NewUnauthenticatedCipher([]byte(key), make([]byte, chacha20.NonceSize))
		if err != nil {
			fmt.Println("Error when decoding chacha20", err)
			return "", err
		}
		plaintext = make([]byte, len(ciphertext))
		cc.XORKeyStream(plaintext, ciphertext)
	}
	return string(plaintext), nil
}

// Download any attachments in a message list
func downloadAttachments(messageArray []MessageStruct) error {
	if len(messageArray) == 0 {
		return errors.New("messageArray Len Error")
	}

	os.Mkdir(attachmentsDir, 0755)
	decrypted_path := "./JMESSAGE_ATTACHMENTS_DECRYPTED"
	os.Mkdir(decrypted_path, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")
			//parse url
			parse1 := strings.Index(string(messageArray[i].url), "?KEY=")
			parsed_url := string(messageArray[i].url[:parse1])
			err := downloadFileFromServer(parsed_url, localPath)
			if err == nil {
				messageArray[i].localPath = localPath
			} else {
				fmt.Println(err)
			}
			targetPath := filepath.Join(decrypted_path, "attachment_"+hex.EncodeToString(randBytes)+".dat")
			data, err := decryptAttachemt(messageArray[i], localPath, targetPath)
			if err != nil {
				return err
			}
			err = saveDecryptedAttachment(data, targetPath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)
		if messageArray[i].localPath == "" {
			fmt.Printf(messageArray[i].decrypted)
		}
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct

	// TODO: IMPLEMENT :: SOLVED
	p := ecdh.P256()
	a, err := p.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("encSK generation failed", err)
		return pubKey, privKey, err
	}
	encSK, err := x509.MarshalPKCS8PrivateKey(a)
	if err != nil {
		fmt.Println("encSK marshal failed", err.Error())
		return pubKey, privKey, err
	}

	//encode pk as encPK
	encPkECDH := a.PublicKey()
	encPK, err := x509.MarshalPKIXPublicKey(encPkECDH)
	if err != nil {
		fmt.Println("encPK generation failed", err)
		return pubKey, privKey, err
	}

	//encode b as sigSK
	b, err := p.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("sigSK generation failed", err)
		return pubKey, privKey, err
	}
	sigSK, err := x509.MarshalPKCS8PrivateKey(b)
	if err != nil {
		fmt.Println("sigSK marshal failed", err)
		return pubKey, privKey, err
	}

	//encode pk as sigPK
	sigPk := b.PublicKey()
	sigPK, err := x509.MarshalPKIXPublicKey(sigPk)
	if err != nil {
		fmt.Println("sigPK marshal failed", err)
		return pubKey, privKey, err
	}
	encPK_base64 := base64.StdEncoding.EncodeToString([]byte(encPK))
	sigPK_base64 := base64.StdEncoding.EncodeToString([]byte(sigPK))
	encSK_base64 := base64.StdEncoding.EncodeToString([]byte(encSK))
	sigSK_base64 := base64.StdEncoding.EncodeToString([]byte(sigSK))

	pubKey.EncPK = string(encPK_base64)
	pubKey.SigPK = string(sigPK_base64)
	privKey.EncSK = string(encSK_base64)
	privKey.SigSK = string(sigSK_base64)

	return pubKey, privKey, err
}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.Parse()

	// Set the server protocol to http or https
	if noTLS == false {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if strictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// If we are registering a new username, let's do that first
	if doUserRegister == true {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Gerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err = generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if headlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				downloadAttachments(messageList)
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				ciphertext := parts[2] + "_ciphtertext"
				MSGURL, err := encryptAttachment(strings.TrimSpace(parts[2]), ciphertext)
				if err != nil {
					fmt.Println("--- ERROR: attachment encryption failed")
				} else {
					fmt.Println("--- message attachment encryption successfully!")
					err = doReadAndSendMessage(strings.TrimSpace(parts[1]), MSGURL)
					if err != nil {
						fmt.Println("--- ERROR: attachment message send failed")
					} else {
						fmt.Println("--- message attachment sent successfully!")
					}

				}
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")
		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
