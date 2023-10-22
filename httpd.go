package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

const logFile = "log/access.log"
const passwdFile = "conf/passwd"
const loginHtml = "html/login.html"
const rootPath = "html"
const defaultPage = rootPath + "/main.html"

type Auth struct {
	Pwd string `json:"pwd"`
}

var ipAddr = flag.String("ip", "127.0.0.1:80", "ip address")
var cookie map[string]int64 //check cookie
var passwd map[string]bool  //check password

func genCookie() string {
	t := time.Now().Unix()

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1).Int63()

	ts := strconv.FormatInt(t, 10) + strconv.FormatInt(r1, 10)
	//log.Println("raw cookie:", ts)
	cookie[ts] = t
	return ts
}

func checkCookie(ck string) bool {
	_, ok := cookie[ck]
	if ok {
		return true
	} else {
		return false
	}
}

const TIMEOUT = 600

func destoryCookie() {
	for true {
		now := time.Now().Unix()
		for key, t := range cookie {
			if now-t > TIMEOUT {
				delete(cookie, key)
			}
		}
		time.Sleep(TIMEOUT * time.Second)
	}
}

// redirct to login
func getRoot(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("cc")
	if err != nil { //no cookie
		log.Println(r.RemoteAddr, "access site")
		http.ServeFile(w, r, loginHtml)
		return
	} else { // cookie
		if checkCookie(ck.Value) == true { //cookie is ok
			if len(r.URL.Path) > 0 {
				//fmt.Println("access:",r.URL.Path)
                if(r.URL.Path == "/") {
					http.ServeFile(w, r, defaultPage)
					return
			    } else {
				    filePath := rootPath + r.URL.Path
				    _, err := os.Stat(filePath)
				    if err == nil {
					    http.ServeFile(w, r, filePath)
					    return
				    } else {
						log.Println(filePath, "not exist")
					}
			   }
			}
		} else { //cookie timeout
			http.ServeFile(w, r, loginHtml)
			return
		}
	}
	w.WriteHeader(404)
	w.Write([]byte("success"))
}

// check password and set cookie
func getLogin(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr, " login")
	len := r.ContentLength
	if len <= 0 {
		return
	}
	// 新建一个字节切片，长度与请求报文的内容长度相同
	body := make([]byte, len)
	// 读取 r 的请求主体，并将具体内容读入 body 中
	r.Body.Read(body)
	// 将字节切片内容写入相应报文
	//fmt.Println("raw body is: ", string(body), "\n")

	var auth Auth
	if err := json.Unmarshal([]byte(body), &auth); err != nil {
		w.WriteHeader(401)
		w.Write([]byte("failed"))
		return
	}
	//check password
	_, ok := passwd[auth.Pwd]
	if ok {
		log.Println(r.RemoteAddr, " auth success")
		cookie := http.Cookie{
			Name:     "cc",
			Value:    genCookie(),
			HttpOnly: true,
			Path:     "/",
			Expires:  time.Now().AddDate(0, 0, 1),
		}
		log.Println("login success ", r.RemoteAddr)
		http.SetCookie(w, &cookie)
		w.WriteHeader(200)
		w.Write([]byte("success"))
	} else {
		log.Println(r.RemoteAddr, " auth failed")
		w.WriteHeader(401)
		w.Write([]byte("failed"))
	}
}

func main() {
	//init log

	flag.Parse()
    log.Println("ipAddr: ", ipAddr)
	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	// optional: log date-time, filename, and line number
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	initResource()

	if loadPasswd() == false {
		log.Println("fail to load 'passwd'\nexit\n")
		return
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:           *ipAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	//auth
	mux.HandleFunc("/login", getLogin)

	//other
	mux.HandleFunc("/", getRoot)
	go destoryCookie()
	err = server.ListenAndServe()
	if err != nil {
		log.Println(err)
	}
}

func initResource() {
	passwd = make(map[string]bool, 10)
	cookie = make(map[string]int64, 100)
}

func loadPasswd() bool {
	f, err := os.Open(passwdFile)
	if err != nil {
		log.Println("Err: ", err)
		return false
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		bytes, _, err := r.ReadLine()
		if err == io.EOF {
			break
		} else {
			passwd[string(bytes)] = true
		}
	}
	//dump key
	for key, flag := range passwd {
		log.Println(key, flag)
	}
	return true
}