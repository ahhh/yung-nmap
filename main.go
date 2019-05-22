// Yung-Nmap the Nmap Wrapper
package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/fatih/color"
)

var serverLog *os.File

var (
	inputList = flag.String("input", "", "this is the input list of multiple / large cidr ranges. It is a path to a file on disk, where each line is a network range")
	countList = flag.String("count", "", "a file with a list of large cidr nets to count the total list of IPs")

	comboDir = flag.String("combodir", "", "a directory to parse for xml files to combine")
	comboOut = flag.String("comboout", "", "a file to output xml files to")

	xmlDir  = flag.String("xmlDir", "", "a directory full of xml files to turn into a csv file")
	csvFile = flag.String("csvFile", "", "a csv output file")

	logName = flag.String("logName", "logFile.txt", "indicate a file to log verbosly to")
	log     = flag.Bool("log", false, "indicate a file to log successful auths to")

	cLog = flag.String("clog", "", "if this flag is specified it will save the class c net division to an outfile")
)

func main() {

	// Parse flags
	flag.Parse()

	// Get current working path
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	logz := flag.Lookup("logName")
	if *log != true {
		message("note", "Logging not enabled!")
	} else {
		// Server Logging
		if _, err := os.Stat(filepath.Join(exPath, logz.Value.String())); os.IsNotExist(err) {
			os.Create(filepath.Join(exPath, logz.Value.String()))
		}
		var errLog error
		serverLog, errLog = os.OpenFile(filepath.Join(exPath, logz.Value.String()), os.O_APPEND|os.O_WRONLY, 0600)
		if errLog != nil {
			color.Red("[!] " + errLog.Error())
		}
		defer serverLog.Close()
		message("info", "log file created at: "+filepath.Join(exPath, logz.Value.String()))
	}

	// New Run!
	message("info", "Starting new run at: "+fmt.Sprintf("%s", time.Now()))

	// Check for a counter run
	counterz := flag.Lookup("count")
	if counterz.Value.String() != "" {
		message("info", "Running a count function")
		cidrNets := readLines(counterz.Value.String())
		count := CountIPs(cidrNets)
		message("success", "Total number of IPs: "+strconv.Itoa(int(count)))
		return
	}

	// Check for a convert xml to csv run
	xdir := flag.Lookup("xmlDir")
	cvfile := flag.Lookup("csvFile")
	if xdir.Value.String() != "" && cvfile.Value.String() != "" {
		message("info", "Running a convert xml to csv function")
		XMLtoCSV(xdir.Value.String(), cvfile.Value.String())
		message("success", "Done XMLtoCSV!")
		return
	}

	// Check for a combo out run
	comdir := flag.Lookup("combodir")
	comout := flag.Lookup("comboout")
	if comdir.Value.String() != "" && comout.Value.String() != "" {
		message("info", "Running a combo out function")
		CombineOutput(comdir.Value.String(), comout.Value.String())
		message("success", "Done Comboout!")
		return
	}

	// Open input list
	inFile := flag.Lookup("input")
	if inFile.Value.String() == "" {
		message("warn", "No input file provided! Please specify a -input ")
		return
	}
	cidrNets := readLines(inFile.Value.String())
	//message("info", fmt.Sprintf("%v", cidrNets))

	// parse each network into a master list of multiple class Cs (recursivly break down the networks?) (print this list to the log)
	masterScanList := BreakDownClassCs(cidrNets)
	message("info", strings.Join(masterScanList, "\n"))
	coutFile := flag.Lookup("clog")
	if coutFile.Value.String() != "" {
		if _, err := os.Stat(filepath.Join(exPath, coutFile.Value.String())); os.IsNotExist(err) {
			os.Create(filepath.Join(exPath, coutFile.Value.String()))
		}
		cFile, errLog := os.OpenFile(coutFile.Value.String(), os.O_APPEND|os.O_WRONLY, 0600)
		if errLog != nil {
			message("warn", errLog.Error())
		}
		defer serverLog.Close()
		cFile.WriteString(strings.Join(masterScanList, "\n"))
		message("success", "wrote c nets to :"+coutFile.Value.String())
		return
	}

	// Begin scanning each class C using nmap lib w/ strong scanning settings
	message("info", "STARTING SCANNING")
	err = TurboScanList(masterScanList)
	if err == nil {
		message("success", "DONE SCANNING")
	}
}

// CombineOutput takes a directory full of nmap xml output and combines them into a single xml file of HOST objects
// Drops hosts that don't have any open ports
func CombineOutput(parseDir, outfile string) {
	var hostsWOpenPorts []nmap.Host
	// for all files in target dir
	files, err := ioutil.ReadDir(parseDir)
	if err != nil {
		message("warn", err.Error())
	}
	for _, file := range files {
		// files ending in xml
		if strings.Contains(file.Name(), ".xml") {
			messageTxt := "Adding " + file.Name()
			message("info", messageTxt)
			dataz, err := ioutil.ReadFile(parseDir + file.Name())
			if err != nil {
				message("warn", err.Error())
			}
			// parse using nmap lib
			result, err := nmap.Parse(dataz)
			if err != nil {
				message("warn", err.Error())
			}
			// Create a master host list of hosts w/ open ports
			for _, singHost := range result.Hosts {
				for _, sp := range singHost.Ports {
					if sp.Status() == "open" {
						hostsWOpenPorts = append(hostsWOpenPorts, singHost)
					}
				}
			}
		}
	}
	// Marshal up some xml and write this megastruct to a file
	XML, err := xml.Marshal(hostsWOpenPorts)
	if err != nil {
		message("warn", err.Error())
	}
	// Wrap the host structure in some meta tags
	XML = append([]byte("<Hosts>"), XML...)
	XML = append(XML, []byte("</Hosts>")...)
	// Write file
	err = ioutil.WriteFile(outfile, XML, 0644)
	if err != nil {
		message("warn", err.Error())
	}
	messageTxt2 := "Combined all of " + parseDir + "*.xml into " + outfile
	message("success", messageTxt2)
}

// Hosts struct that is created when wrapping the nmap xml scan output
type Hosts struct {
	Hosts []nmap.Host `xml:"host" json:"hosts"`
}

// XMLtoCSV is a func that takes an XML file w/ nmap HOST objects and converts them to a CSV file with a host and port per line
func XMLtoCSV(xmlDir, csvFile string) {
	if _, err := os.Stat(csvFile); os.IsNotExist(err) {
		os.Create(csvFile)
	}
	var errLog error
	csvLog, errLog := os.OpenFile(csvFile, os.O_APPEND|os.O_WRONLY, 0600)
	if errLog != nil {
		message("warn", errLog.Error())
	}

	startLine := fmt.Sprintln("IP,Port,SvcName")
	csvLog.WriteString(startLine)
	files, err := ioutil.ReadDir(xmlDir)
	if err != nil {
		message("warn", err.Error())
	}
	for _, file := range files {
		// files ending in xml
		if strings.Contains(file.Name(), ".xml") {
			messageTxt := "Adding " + file.Name()
			message("info", messageTxt)
			dataz, err := ioutil.ReadFile(xmlDir + file.Name())
			if err != nil {
				message("warn", err.Error())
			}
			// parse using nmap lib
			result, err := nmap.Parse(dataz)
			if err != nil {
				message("warn", err.Error())
			}
			// Create a master host list of hosts w/ open ports
			for _, singHost := range result.Hosts {
				for _, sp := range singHost.Ports {
					if sp.Status() == "open" {
						openLine := fmt.Sprintf("%+v,%v,%s\n", singHost.Addresses, sp.ID, sp.Service.Name)
						csvLog.WriteString(openLine)
					}
				}
			}
		}
	}
	message("success", "Done creating CSV file "+csvFile+" from "+xmlDir+"/*.xml")
}

// CountIPs is a function to list the total number of individual addresses in a file full of cidr netblocks
func CountIPs(listOfCIDRs []string) uint64 {
	counter := uint64(0)
	for _, cidrRange := range listOfCIDRs {
		_, inet, _ := net.ParseCIDR(cidrRange)
		counter += cidr.AddressCount(inet)
	}
	return counter
}

// BreakDownClassCs will take a list of CIDR notation netblocks and return a list of CIDR notation Class C netblocks
// Anything smaller than a class C (or a class C) is passed through, anything larger gets broken down
func BreakDownClassCs(listOfcidrnets []string) []string {
	var expandedList []string
	for _, cidrnet := range listOfcidrnets {
		rangeSplit := strings.Split(cidrnet, "/")
		cidrGuy, _ := strconv.Atoi(rangeSplit[1])
		if cidrGuy < 24 {
			var numberOfClassCs float64
			cidrMod := 24 - cidrGuy
			if cidrMod == 1 {
				numberOfClassCs = 2
			} else {
				numberOfClassCs = math.Pow(2, float64(cidrMod))
			}
			// Now that we know how many Class Cs we create from here, lets do it
			// Start at the first range
			base := rangeSplit[0]
			for i := float64(0); i < numberOfClassCs; i++ {
				base = base + "/24"
				_, inet, err := net.ParseCIDR(base)
				if err != nil {
					message("warn", "error breaking down Class C networks")
					return nil
				}
				_, last := cidr.AddressRange(inet)
				expandedList = append(expandedList, base)
				newBase := cidr.Inc(last)
				//fmt.Println(newBase)
				base = newBase.String()
			}
		} else {
			expandedList = append(expandedList, cidrnet)
		}
	}
	return expandedList
}

// TurboScanList is a function that shells out to nmap and scans a huge list of ranges each as an individual scan
func TurboScanList(netRanges []string) error {
	for i, cidrRange := range netRanges {
		message("note", fmt.Sprintf("On %d of %d", int(i), int(len(netRanges))))
		message("info", fmt.Sprintf("Starting %s", cidrRange))
		outfile := strings.Split(cidrRange, "/")
		// Shoutout to @indi303 for the turbo nmap scan!
		arguments := fmt.Sprintf("-sS -Pn -PP -PE -PM -PI -PA20,53,80,113,443,5060,10043 --open --min-hostgroup=255 --host-timeout=300m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --stats-every=10s -PS1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,110-111,113,123,135,137,139,143,179,222,384,389,407,443,445,465,500,512-515,540,548,554,587,617,623,689,705,783,910,912,921,993,995,1000,1024,1099-1100,1220,1300,1352,1433-1435,1494,1521,1533,1581-1582,1604,1720,1723,1755,1900,2000,2049,2100,2103,2121,2207,2222,2323,2380,2525,2533,2598,2638,2947,2967,3000,3050,3057,3128,3306,3389,3628,3632,3690,3780,3790,4000,4445,4848,5051,5060-5061,5093,5168,5250,5405,5432-5433,5554-5555,5800,6050,6060,6070,6080,6101,6112,6502-6504,6660,6667,6905,7080,7144,7510,7579-7580,7777,7787,8000,8008,8014,8028,8080-8081,8090,8180,8222,8300,8333,8443-8444,8800,8812,8880,8888,8899,9080-9081,9090,9111,9152,9495,9999-10001,10050,10202-10203,10443,10616,10628,11000,11234,12174,12203,12401,13500,14330,16102,18881,19300,19810,20031,20034,20222,22222,25000,25025,26000,28222,30000,34443,38080,38292,41025,41523-41524,44334,46823,50000-50004,50013,57772,62078,62514,65535 --min-rate=1000 --max-retries=0 -n -T5 -PU47911 -p1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,110-111,113,123,135,137,139,143,179,222,384,389,407,443,445,465,500,512-515,540,548,554,587,617,623,689,705,783,910,912,921,993,995,1000,1024,1099-1100,1220,1300,1352,1433-1435,1494,1521,1533,1581-1582,1604,1720,1723,1755,1900,2000,2049,2100,2103,2121,2207,2222,2323,2380,2525,2533,2598,2638,2947,2967,3000,3050,3057,3128,3306,3389,3628,3632,3690,3780,3790,4000,4445,4848,5051,5060-5061,5093,5168,5250,5405,5432-5433,5554-5555,5800,6050,6060,6070,6080,6101,6112,6502-6504,6660,6667,6905,7080,7144,7510,7579-7580,7777,7787,8000,8008,8014,8028,8080-8081,8090,8180,8222,8300,8333,8443-8444,8800,8812,8880,8888,8899,9080-9081,9090,9111,9152,9495,9999-10001,10050,10202-10203,10443,10616,10628,11000,11234,12174,12203,12401,13500,14330,16102,18881,19300,19810,20031,20034,20222,22222,25000,25025,26000,28222,30000,34443,38080,38292,41025,41523-41524,44334,46823,50000-50004,50013,57772,62078,62514,65535 -oA=%s %s", outfile[0], cidrRange)
		//message("info", fmt.Sprintf("nmap command: nmap %s", arguments))
		cmd := exec.Command("nmap", strings.Split(arguments, " ")...)
		// for debuging
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			message("warn", fmt.Sprintf("cmd.Run() failed with %s\n", err))
			return err
		}
		message("success", fmt.Sprintf("Finsihed scanning %s", cidrRange))
	}
	return nil
}

// Message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
		if *log == true {
			server("info: " + message)
		}
	case "note":
		color.Yellow("[-]" + message)
		if *log == true {
			server("note: " + message)
		}
	case "warn":
		color.Red("[!]" + message)
		if *log == true {
			server("warning: " + message)
		}
	case "debug":
		color.Red("[DEBUG]" + message)
		if *log == true {
			server("debug: " + message)
		}
	case "success":
		color.Green("[+]" + message)
		if *log == true {
			server("success: " + message)
		}
	default:
		color.Red("[_-_]Invalid message level: " + message)
		if *log == true {
			server("invalid: " + message)
		}
	}
}

// Server is a private function used to write Messages to the log file
func server(logMessage string) {
	serverLog.WriteString(fmt.Sprintf("[%s] - %s\r\n", time.Now(), logMessage))
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
