// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
)


type NetConf struct {
	types.NetConf
	Master string `json:"master"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Master == "" {
		return nil, "", fmt.Errorf(`"master" field is required. It specifies the host interface name to virtualize`)
	}
	return n, n.CNIVersion, nil
}

func setupVF(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, error) {
	vf := &current.Interface{}

	vfIdx := 0
	masterName := conf.Master

	m, err := netlink.LinkByName(masterName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", conf.Master, err)
	}

	vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d/net", masterName, vfIdx)
	if _, err := os.Lstat(vfDir); err != nil {
		return nil, err
	}

	infos, err := ioutil.ReadDir(vfDir)
	if err != nil {
		return nil, err
	}

	if len(infos) != 1 {
		return nil, fmt.Errorf("no network devices in directory %s", vfDir)
	}

	// VF NIC name
	vfDevName := infos[0].Name()
	vfDev, err := netlink.LinkByName(vfDevName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup vf device %q: %v", vfDevName, err)
	}

	macAddr, err := net.ParseMAC("66:d8:02:77:aa:aa")
	if err != nil {
		return nil, err
	}
	if err = netlink.LinkSetVfHardwareAddr(m, vfIdx, macAddr); err != nil {
		return nil, fmt.Errorf("failed to set vf %d macaddress: %v", vfIdx, err)
	}

	if err = netlink.LinkSetVfVlan(m, vfIdx, 1518); err != nil {
		return nil, fmt.Errorf("failed to set vf %d vlan: %v", vfIdx, err)
	}

	if err = netlink.LinkSetUp(vfDev); err != nil {
		return nil, fmt.Errorf("failed to setup vf %d device: %v", vfIdx, err)
	}

	// move VF device to ns
	if err = netlink.LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
		return nil, fmt.Errorf("failed to move vf %d to netns: %v", vfIdx, err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(vfDevName, ifName)
		if err != nil {
			return fmt.Errorf("failed to rename vf %d device %q to %q: %v", vfIdx, vfDevName, ifName, err)
		}
		vf.Name = ifName

		// Re-fetch macvlan to get all properties/attributes
		contVF, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch vf %q: %v", ifName, err)
		}
		vf.Mac = contVF.Attrs().HardwareAddr.String()
		vf.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return vf, nil
}

func releaseVF(conf *NetConf, ifName string, netns ns.NetNS) error {
	vfIdx := 0

	initns, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to get init netns: %v", err)
	}

	if err = netns.Set(); err != nil {
		return fmt.Errorf("failed to enter netns %q: %v", netns, err)
	}

	// get VF device
	vfDev, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup vf %d device %q: %v", vfIdx, ifName, err)
	}

	// device name in init netns
	index := vfDev.Attrs().Index
	devName := fmt.Sprintf("dev%d", index)

	// shutdown VF device
	if err = netlink.LinkSetDown(vfDev); err != nil {
		return fmt.Errorf("failed to down vf %d device: %v", vfIdx, err)
	}

	// rename VF device
	err = ip.RenameLink(ifName, devName)
	if err != nil {
		return fmt.Errorf("failed to rename vf %d evice %q to %q: %v", vfIdx, ifName, devName, err)
	}

	// move VF device to init netns
	if err = netlink.LinkSetNsFd(vfDev, int(initns.Fd())); err != nil {
		return fmt.Errorf("failed to move vf %d to init netns: %v", vfIdx, err)
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	vfInterface, err := setupVF(n, args.IfName, netns)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	result.Interfaces = []*current.Interface{vfInterface}

	var firstV4Addr net.IP
	for _, ipc := range result.IPs {
		// All addresses apply to the container macvlan interface
		ipc.Interface = 0

		if ipc.Address.IP.To4() != nil && firstV4Addr == nil {
			firstV4Addr = ipc.Address.IP
		}
	}

	if firstV4Addr != nil {
		err = netns.Do(func(_ ns.NetNS) error {
			// if err := ip.SetHWAddrByIP(args.IfName, firstV4Addr, nil /* TODO IPv6 */); err != nil {
			// 	return err
			// }

			return ipam.ConfigureIface(args.IfName, result)
		})
		if err != nil {
			return err
		}
	}

	// err = netns.Do(func(_ ns.NetNS) error {
	// 	link, err := netlink.LinkByName(args.IfName)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to re-fetch vf interface: %v", err)
	// 	}
	// 	// vfInterface.Mac = link.Attrs().HardwareAddr.String()
	// 	return nil
	// })
	// if err != nil {
	// 	return err
	// }

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	if err = releaseVF(n, args.IfName, netns); err != nil {
		return err
	}

	err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
