// 极域学生机局域网 IP 扫描器 (Go 版, 纯标准库, 跨平台)
//
// 用途:
//   自动探测本机网段 -> 并行 ping + ARP 发现在线主机 -> 英文分号(;)拼接
//   -> 复制到系统剪贴板(Windows 用 cmd/clip) -> 交互式剔除 -> 再次复制。
//   无任何外部依赖，编译出的 .exe 在没装 Python 的 Windows 上双击即用。
//
// 用法:
//   自动探测网段:  jiyu-scanner.exe
//   手动指定网段:  jiyu-scanner.exe 192.168.1.0/24
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type hostInfo struct {
	ip  string
	mac string
}

// ---------- 基础网络 ----------

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func broadcast(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := net.IP(ipnet.Mask).To4()
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

func buildIPNet(ip, maskStr string) *net.IPNet {
	ipAddr := net.ParseIP(ip)
	nmAddr := net.ParseIP(maskStr)
	if ipAddr == nil || nmAddr == nil {
		return nil
	}
	mask := net.IPMask(nmAddr.To4())
	return &net.IPNet{IP: ipAddr.Mask(mask), Mask: mask}
}

func hexMaskToDotted(h string) string {
	v, err := strconv.ParseUint(h, 0, 32)
	if err != nil {
		return ""
	}
	b := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		b[3-i] = byte(v >> (8 * uint(i)))
	}
	return b.String()
}

// ---------- 网段探测 ----------

func detectSubnet(ip string) (string, string) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("ipconfig").Output()
		if err == nil {
			blocks := regexp.MustCompile(`\r?\n\s*\r?\n`).Split(string(out), -1)
			for _, b := range blocks {
				if strings.Contains(b, ip) {
					mIP := regexp.MustCompile(`IPv4 Address[ .:]+(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(b)
					mNM := regexp.MustCompile(`Subnet Mask[ .:]+(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(b)
					if mIP != nil && mNM != nil {
						if n := buildIPNet(ip, mNM[1]); n != nil {
							return n.String(), broadcast(n).String()
						}
					}
				}
			}
		}
	case "darwin":
		out, err := exec.Command("ifconfig").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				mInet := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(line)
				if mInet != nil && mInet[1] == ip {
					mDot := regexp.MustCompile(`netmask (\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(line)
					mHex := regexp.MustCompile(`netmask (0x[0-9a-fA-F]{8})`).FindStringSubmatch(line)
					var nm string
					if mDot != nil {
						nm = mDot[1]
					} else if mHex != nil {
						nm = hexMaskToDotted(mHex[1])
					}
					if nm != "" {
						if n := buildIPNet(ip, nm); n != nil {
							return n.String(), broadcast(n).String()
						}
					}
				}
			}
		}
	}
	if n := buildIPNet(ip, "255.255.255.0"); n != nil {
		return n.String(), broadcast(n).String()
	}
	return "", ""
}

// ---------- ping / ARP ----------

func ping(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", "500", "-t", "1", ip)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}

func arpTable() map[string]string {
	m := map[string]string{}
	var out []byte
	var err error
	switch runtime.GOOS {
	case "windows":
		out, err = exec.Command("arp", "-a").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				mm := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})`).FindStringSubmatch(line)
				if mm != nil {
					m[mm[1]] = strings.ToLower(strings.ReplaceAll(mm[2], "-", ":"))
				}
			}
		}
	case "darwin":
		out, err = exec.Command("arp", "-an").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				mm := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17}|\(incomplete\))`).FindStringSubmatch(line)
				if mm != nil && mm[2] != "(incomplete)" {
					m[mm[1]] = strings.ToLower(mm[2])
				}
			}
		}
	default:
		out, err = exec.Command("ip", "neigh", "show").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				mm := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F:]{17})`).FindStringSubmatch(line)
				if mm != nil {
					m[mm[1]] = strings.ToLower(mm[2])
				}
			}
		}
	}
	return m
}

// ---------- 核心发现 ----------

func incIP(ip []byte) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func cmpIP(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

func discover(cidr, local string) []hostInfo {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	base := ipnet.IP.To4()
	bc := broadcast(ipnet).To4()
	if base == nil || bc == nil {
		return nil
	}
	var ips []string
	cur := append([]byte(nil), base...)
	for {
		incIP(cur)
		if cmpIP(cur, bc) >= 0 { // 到广播地址即停(广播地址不扫描)
			break
		}
		ips = append(ips, net.IP(append([]byte(nil), cur...)).String())
	}

	arp1 := arpTable()
	type res struct {
		ip  string
		mac string
		ok  bool
	}
	results := make([]res, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 80)
	for i, ip := range ips {
		if ip == local {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			replied := ping(ip)
			mac := arp1[ip]
			results[i] = res{ip: ip, mac: mac, ok: replied || mac != ""}
		}(i, ip)
	}
	wg.Wait()

	arp2 := arpTable()
	var out []hostInfo
	for _, r := range results {
		if r.ip == local {
			continue
		}
		if r.ok || arp2[r.ip] != "" {
			mac := r.mac
			if mac == "" {
				mac = arp2[r.ip]
			}
			out = append(out, hostInfo{ip: r.ip, mac: mac})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a := net.ParseIP(out[i].ip)
		b := net.ParseIP(out[j].ip)
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
	return out
}

// ---------- 剪贴板 ----------

func copyClipboard(s string) bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "clip")
		cmd.Stdin = strings.NewReader(s)
		if cmd.Run() == nil {
			return true
		}
		cmd2 := exec.Command("powershell", "-Command", "$input | Set-Clipboard")
		cmd2.Stdin = strings.NewReader(s)
		return cmd2.Run() == nil
	}
	// 非 Windows 仅用于本地测试: 不真正写剪贴板
	return false
}

// ---------- 工具 ----------

func join(hosts []hostInfo) string {
	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips = append(ips, h.ip)
	}
	return strings.Join(ips, ";")
}

// ---------- 主流程 ----------

func main() {
	local := localIP()
	cidr, bcast := detectSubnet(local)
	if len(os.Args) > 1 {
		cidr = os.Args[1]
		if n := buildIPNet(strings.Split(cidr, "/")[0], maskFromCIDR(cidr)); n != nil {
			bcast = broadcast(n).String()
		}
	}
	if cidr == "" {
		fmt.Println("无法探测网段，请用参数指定，例如: jiyu-scanner.exe 192.168.1.0/24")
		return
	}
	fmt.Printf("本机 IP : %s\n", local)
	fmt.Printf("扫描网段: %s  (广播地址: %s)\n", cidr, bcast)

	fmt.Println("扫描中，请稍候...")
	found := discover(cidr, local)

	fmt.Printf("\n发现 %d 台在线主机:\n", len(found))
	for i, h := range found {
		fmt.Printf("  [%2d] %s  %s\n", i+1, h.ip, h.mac)
	}

	joined := join(found)
	fmt.Println("\n分号拼接结果:")
	fmt.Println(joined)
	if copyClipboard(joined) {
		fmt.Println("\n[已复制到剪贴板] 直接 Ctrl+V 粘贴进「IP 地址」栏即可。")
	} else {
		fmt.Println("\n[复制失败] 请手动复制上面的结果(Windows 下才会自动复制)。")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n如需剔除某些主机，输入序号(空格分隔，直接回车=全部保留): ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line != "" {
		exclude := map[int]bool{}
		for _, p := range strings.Fields(line) {
			if n, err := strconv.Atoi(p); err == nil {
				exclude[n-1] = true
			}
		}
		var kept []hostInfo
		for i, h := range found {
			if !exclude[i] {
				kept = append(kept, h)
			}
		}
		joined = join(kept)
		fmt.Println("\n重新拼接结果:")
		fmt.Println(joined)
		if copyClipboard(joined) {
			fmt.Println("[已重新复制到剪贴板]")
		}
	}

	fmt.Println("\n按回车退出...")
	reader.ReadString('\n')
}

func maskFromCIDR(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "255.255.255.0"
	}
	m := net.IP(ipnet.Mask).To4()
	if m == nil {
		return "255.255.255.0"
	}
	return m.String()
}
