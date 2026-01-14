package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type Domain struct {
	Domain      string `json:"domain"`
	Webroot     string `json:"webroot"`
	InstallPath string `json:"install_path"`
}

type Config struct {
	Email     string   `json:"email"`
	RenewDays int      `json:"renew_days"`
	WebEnable bool     `json:"web_enable"`
	WebUser   string   `json:"web_user"`
	WebPass   string   `json:"web_pass"`
	Domains   []Domain `json:"domains"`
}

var (
	cfg      Config
	basePath string
	logFile  *os.File
)

func safePath(p string) string { return filepath.Join(basePath, p) }

func initBasePath() {
	exe, _ := os.Executable()
	basePath = filepath.Dir(exe)
}

func cleanOldLog() {
	p := safePath("domain-cert.log")
	if fi, err := os.Stat(p); err == nil && time.Since(fi.ModTime()) > 30*24*time.Hour {
		os.Remove(p)
	}
}

func initLog() {
	f, _ := os.OpenFile(safePath("domain-cert.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	log.SetOutput(f)
	logFile = f
}

func logStep(name string, fn func() error) {
	start := time.Now()
	log.Printf("[STEP] %s 开始\n", name)
	err := fn()
	cost := time.Since(start).Seconds()
	if err != nil {
		log.Printf("[STEP] %s 失败 (%.2fs): %v\n", name, cost, err)
	} else {
		log.Printf("[STEP] %s 成功 (%.2fs)\n", name, cost)
	}
}

func initFiles() {
	cfgPath := safePath("config.json")
	webPath := safePath("web/index.html")

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		os.WriteFile(cfgPath, []byte(`{
  "email": "example@qq.com",
  "renew_days": 60,
  "web_enable": true,
  "web_user": "admin",
  "web_pass": "123456",
  "domains": [
    {
      "domain": "example.com",
      "webroot": "/www/wwwroot/example.com",
      "install_path": "/www/server/panel/vhost/cert/example.com"
    }
  ]
}`), 0644)
	}

	if _, err := os.Stat(webPath); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(webPath), 0755)
		os.WriteFile(webPath, []byte(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>域名证书管理</title></head>
<body>
<h2>域名 SSL 管理</h2>
<textarea id="cfg" style="width:700px;height:350px;"></textarea><br>
<button onclick="save()">保存配置</button>
<button onclick="issue()">签发证书</button>
<div id="msg" style="color:green;margin-top:10px;"></div>
<script>
fetch('/api/config').then(r=>r.json()).then(j=>{
 document.getElementById('cfg').value=JSON.stringify(j,null,2)
})
function flash(t,c){
 let m=document.getElementById('msg');m.style.color=c;m.innerText=t;
 setTimeout(()=>m.innerText='',1000)
}
function save(){
 fetch('/api/config',{method:'POST',body:cfg.value}).then(r=>r.text()).then(t=>{
   if(t==='ok') flash('✔ 保存成功','green'); else flash('✖ '+t,'red')
 })
}
function issue(){
 fetch('/api/issue',{method:'POST'}).then(()=>flash('✔ 任务已提交','green'))
}
</script>
</body>
</html>`), 0644)
	}
}

func loadConfig() {
	b, _ := os.ReadFile(safePath("config.json"))
	json.Unmarshal(b, &cfg)
}

func saveConfig(b []byte) error {
	var tmp Config
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	cfg = tmp
	return os.WriteFile(safePath("config.json"), b, 0644)
}

func auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.WebEnable {
			w.WriteHeader(403)
			return
		}
		raw := r.Header.Get("Authorization")
		if raw == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="domain-cert"`)
			w.WriteHeader(401)
			w.Write([]byte("需要登录"))
			return
		}
		d, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "Basic "))
		p := strings.SplitN(string(d), ":", 2)
		if len(p) != 2 || p[0] != cfg.WebUser || p[1] != cfg.WebPass {
			w.WriteHeader(403)
			w.Write([]byte("账号或密码错误"))
			return
		}
		h(w, r)
	}
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "未知外网IP"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout = logFile
	c.Stderr = logFile
	return c.Run()
}

func issueAll() {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[PANIC]", r, string(debug.Stack()))
		}
	}()

	log.Println("[TASK] 证书任务开始")

	logStep("安装 acme.sh", func() error {
		return run("sh", "-c", "curl https://get.acme.sh | sh -s email="+cfg.Email)
	})

	logStep("设置默认 CA", func() error {
		return run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"),
			"--set-default-ca", "--server", "letsencrypt")
	})

	for _, d := range cfg.Domains {
		log.Printf("[DOMAIN] %s 开始\n", d.Domain)

		logStep("申请证书 "+d.Domain, func() error {
			return run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"),
				"--issue", "--server", "letsencrypt",
				"--days", strconv.Itoa(cfg.RenewDays),
				"-d", d.Domain, "-w", d.Webroot)
		})

		logStep("安装证书 "+d.Domain, func() error {
			os.MkdirAll(d.InstallPath, 0755)
			return run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"),
				"--install-cert", "-d", d.Domain,
				"--key-file", d.InstallPath+"/privkey.pem",
				"--fullchain-file", d.InstallPath+"/fullchain.pem")
		})

		log.Printf("[DOMAIN] %s 完成\n", d.Domain)
	}

	log.Println("[TASK] 证书任务结束")
}

func main() {
	initBasePath()
	initFiles()
	cleanOldLog()
	initLog()
	loadConfig()

	fmt.Println("配置文件路径:", safePath("config.json"))
	fmt.Println("管理页面外网地址: http://" + getPublicIP() + ":8081")

	go func() {
		t := time.NewTicker(6 * time.Hour)
		for range t.C {
			log.Println("[TIMER] 定时任务触发")
			issueAll()
		}
	}()

	if cfg.WebEnable {
		mux := http.NewServeMux()
		mux.Handle("/", auth(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, safePath("web/index.html"))
		}))
		mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(cfg)
			} else {
				b, _ := io.ReadAll(r.Body)
				if err := saveConfig(b); err != nil {
					w.Write([]byte("JSON错误: " + err.Error()))
					return
				}
				w.Write([]byte("ok"))
			}
		}))
		mux.HandleFunc("/api/issue", auth(func(w http.ResponseWriter, r *http.Request) {
			go issueAll()
			w.Write([]byte("started"))
		}))
		go http.ListenAndServe(":8081", mux)
	}

	select {}
}
