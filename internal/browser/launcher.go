package browser
import(
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func OpenChrome(proxyAddr string, targetURL string) error{
	var cmd *exec.Cmd
	var args []string
	if targetURL == ""{
		targetURL = "about:blank"
	}

	chromeFlags := []string{
		"--proxy-server=" + proxyAddr,
		"--ignore-certificate-errors",
		"--proxy-bypass-list=<-loopback>",
		"--no-first-run",
		"--disable-default-apps",
		"--no-default-browser-check",
		"--user-data-dir="+os.TempDir()+"/scanner_chrome_profile",
		targetURL,
	}
	
	switch runtime.GOOS{
		case "darwin":
			args = append([]string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}, chromeFlags...)
		case "windows":
			args = append([]string{"cmd", "/C", "start", "chrome"}, chromeFlags...)
		case "linux":
			args = append([]string{"google-chrome"}, chromeFlags...)
		default:
			return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	cmd = exec.Command(args[0], args[1:]...)
	return cmd.Start()
}