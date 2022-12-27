package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/seiferma/nginxmailauthdelegator/internal"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("program arguments invalid. Configuration file has to be first argument.")
		os.Exit(1)
	}

	config_file_path := os.Args[1]
	info, err := os.Stat(config_file_path)
	if err != nil || info.IsDir() {
		log.Fatal("given file path is invalid.")
		os.Exit(1)
	}

	var config internal.Configuration
	if config.Load(config_file_path) != nil {
		log.Fatal("the configuration file could not be loaded.")
		os.Exit(1)
	}

	auth_handler := internal.CreateAuthHandler(config)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		http_handler(w, r, &auth_handler)
	})
	log.Printf("Started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func http_handler(w http.ResponseWriter, r *http.Request, auth_handler *internal.AuthHandler) {

	auth_attempt, err := strconv.Atoi(r.Header.Get("Auth-Login-Attempt"))
	if err != nil {
		report_error("", "internal error (no auth attempts submitted)", "", -1, w)
		return
	}

	auth_protocol := r.Header.Get("Auth-Protocol")
	if auth_protocol != "smtp" && auth_protocol != "imap" {
		report_error("", "internal error (unsupported protocol)", "", -1, w)
		return
	}

	client_ip := r.Header.Get("Client-IP")
	if client_ip == "" {
		report_error(auth_protocol, "internal error (client ip missing)", "", -1, w)
		return
	}

	auth_method := r.Header.Get("Auth-Method")
	if auth_method != "plain" {
		report_error(auth_protocol, "only plain authentication is supported", "504 5.5.4", auth_attempt+1, w)
		return
	}

	auth_ssl := r.Header.Get("Auth-SSL")
	if auth_ssl != "" && auth_ssl != "off" {
		report_error(auth_protocol, "client certificates are not supported", "504 5.5.4", auth_attempt+1, w)
		return
	}

	auth_user := r.Header.Get("Auth-User")
	auth_pass := r.Header.Get("Auth-Pass")

	auth_response := auth_handler.HandleAuthRequest(auth_protocol, auth_user, auth_pass, auth_attempt)

	if auth_response.Status == "OK" {
		if client_ip != "" {
			log.Printf("client [%v] successfully authenticated.", client_ip)
		}
		report_success(auth_response.Server, strconv.Itoa(auth_response.Port), auth_response.User, auth_response.Password, w)
	} else {
		if client_ip != "" {
			log.Printf("client [%v] did not provide valid credentials.", client_ip)
		}
		report_error(auth_protocol, auth_response.Status, auth_response.Error_code, auth_response.Wait, w)
	}
}

func report_success(server, port, user, password string, w http.ResponseWriter) {
	w.Header().Add("Auth-Status", "OK")
	w.Header().Add("Auth-Server", server)
	w.Header().Add("Auth-Port", port)
	if user != "" {
		w.Header().Add("Auth-User", user)
	}
	if password != "" {
		w.Header().Add("Auth-Pass", password)
	}
	w.WriteHeader(200)
}

func report_error(auth_protocol, reason, smtp_code string, tries int, w http.ResponseWriter) {
	w.Header().Add("Auth-Status", reason)
	if auth_protocol == "smtp" {
		w.Header().Add("Auth-Error-Code", smtp_code)
	}
	if tries > 0 {
		w.Header().Add("Auth-Wait", strconv.Itoa(tries))
	}
	w.WriteHeader(200)
}
