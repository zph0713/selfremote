package main

// sr keyedit — 查看 / 修改密钥文件（或明文配置）里的服务端地址。
//
// 用途：服务端公网地址变化时（换运营商、动态 IPv6 前缀更新……），无需去 Web
// 控制面重新生成密钥文件，直接把文件里的 server 字段改成新地址即可。
//
// 加密密钥文件（.srkey）会用同一个文件密码重新封装（换新随机盐），其余字段
// 保持不变；明文 client.json 则直接原地改写。原文件自动备份为 <file>.bak。
//
// 用法：
//
//	sr keyedit -c client.srkey -show                          # 只查看
//	sr keyedit -c client.srkey -server '[240e:1:2::3]:28333'  # 改成新地址
//	sr keyedit -c client.srkey                                # 交互式输入
//
// -kpass / 环境变量 SR_KEYPASS 提供文件密码（自动化用；不填则交互式询问）。

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"selfremote/internal/config"
	"selfremote/internal/keyfile"
)

func cmdKeyedit(args []string) error {
	fs := flag.NewFlagSet("keyedit", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "密钥文件路径（.srkey 或明文 JSON）")
	kpass := fs.String("kpass", "", "密钥文件密码（或环境变量 SR_KEYPASS）")
	newServer := fs.String("server", "", "新的服务端地址，如 '[240e:1:2::3]:28333'；不填则交互式询问")
	show := fs.Bool("show", false, "只显示当前配置，不修改文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("需要 -c <密钥文件>")
	}
	if *show && *newServer != "" {
		return errors.New("-show 和 -server 不能同时使用")
	}
	// Check the new address up front so a typo fails before the passphrase
	// prompt (the core validates again before writing anything).
	if *newServer != "" {
		addr, err := config.NormalizeServerAddr(*newServer)
		if err != nil {
			return err
		}
		*newServer = addr
	}
	return keyedit(*cfgPath, *newServer, *show, *kpass, os.Stdout)
}

// keyedit is the core (testable) implementation of `sr keyedit`.
func keyedit(path, newServer string, showOnly bool, kpass string, out io.Writer) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	envelope := keyfile.IsEnvelope(raw)

	plain := raw
	var sealPass string
	if envelope {
		sealPass = kpass
		if sealPass == "" {
			sealPass = os.Getenv("SR_KEYPASS")
		}
		plain, sealPass, err = unlockKeyfile(raw, sealPass)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "密钥文件已解密（仅保存在内存中）")
	}

	cur, tunnel, routes, err := config.ClientInfo(plain)
	if err != nil {
		return err
	}

	if showOnly {
		kind := "明文 JSON"
		if envelope {
			kind = "加密密钥文件"
		}
		fmt.Fprintf(out, "文件:       %s（%s）\n", path, kind)
		fmt.Fprintf(out, "当前服务端: %s\n", cur)
		fmt.Fprintf(out, "隧道地址:   %s\n", tunnel)
		fmt.Fprintf(out, "路由:       %v\n", routes)
		return nil
	}

	if newServer == "" {
		fmt.Fprintf(out, "当前服务端地址: %s\n", cur)
		fmt.Fprint(os.Stderr, "输入新的服务端地址（如 [240e:1:2::3]:28333；直接回车取消）: ")
		line, err := readLine()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if line == "" {
			fmt.Fprintln(out, "已取消，文件未修改。")
			return nil
		}
		newServer = line
	}

	updated, err := config.SetClientServer(plain, newServer)
	if err != nil {
		return err
	}

	var data []byte
	if envelope {
		if data, err = keyfile.Seal(updated, sealPass); err != nil {
			return fmt.Errorf("重新加密失败: %w", err)
		}
	} else {
		data = updated
	}

	if err := replaceFileWithBackup(path, data); err != nil {
		return err
	}
	fmt.Fprintf(out, "服务端地址已更新: %s → %s\n", cur, newServer)
	if envelope {
		fmt.Fprintln(out, "文件已用原密码重新加密（随机盐已更换）。")
	}
	fmt.Fprintf(out, "原文件已备份为: %s.bak\n", path)
	return nil
}

// replaceFileWithBackup keeps the previous content of path in path+".bak" and
// then atomically replaces path with data (same-directory temp file + rename,
// so an interrupted run never leaves a half-written key file).
func replaceFileWithBackup(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".bak", old, mode); err != nil {
		return fmt.Errorf("写备份失败: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
