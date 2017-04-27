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
	"strings"
	"strconv"

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

func getsriovNumfs(ifName string) (int, error) {
	var vfTotal int

	sriovFile := fmt.Sprintf("/sys/class/net/%s/device/sriov_numvfs", ifName)
	if _, err := os.Lstat(sriovFile); err != nil {
		return vfTotal, fmt.Errorf("failed to open the sriov_numvfs of device %q: %v", ifName, err)
	}

	data, err := ioutil.ReadFile(sriovFile)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to read the sriov_numvfs of device %q: %v", ifName, err)
	}

	if len(data) == 0 {
		return vfTotal, fmt.Errorf("no data in the file %q", sriovFile)
	}

	sriovNumfs := strings.TrimSpace(string(data))
	vfTotal, err = strconv.Atoi(sriovNumfs)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to convert sriov_numvfs(byte value) to int of device %q: %v", ifName, err)
	}

	return vfTotal, nil
}

// @param: masterName 	PF网卡名称
// @param: ifName	映射到容器中的网卡名称
// @param: mac		mac地址
func setupVF(masterName string, ifName string, bo *netlink.Bond, netns ns.NetNS) (*current.Interface, error) {
	vfInterface := &current.Interface{}

	var vfIdx int
	var infos []os.FileInfo


	m, err := netlink.LinkByName(masterName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", masterName, err)
	}

	// 获取物理网卡的Virtual Function的个数
	vfTotal, err := getsriovNumfs(masterName)
	if err != nil {
		return nil, err
	}

	if vfTotal <= 0 {
		return nil, fmt.Errorf("no virtual function in the device %q: %v", ifName)
	}

	for idx := 1; idx <= (vfTotal -1); idx++ {
		vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d/net", masterName, idx)
		if _, err := os.Lstat(vfDir); err != nil {
			if idx == (vfTotal - 1) {
				return nil, fmt.Errorf("failed to open the virtfn%d dir of the device %q: %v", idx, masterName, err)
			}
			continue
		}

		infos, err = ioutil.ReadDir(vfDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read the virtfn%d dir of the device %q: %v", idx, masterName, err)
		}

		if (len(infos) == 0) && (idx == (vfTotal - 1)) {
			return nil, fmt.Errorf("no Virtual function exist in directory %s, last idx is virtfn%d", vfDir, idx)
		}

		if (len(infos) == 0) && (idx != (vfTotal - 1)) {
			continue
		} else {
			vfIdx = idx
			break
		}
		
	}

	if len(infos) != 1 {
		return nil, fmt.Errorf("no network devices avaiable for the %q", masterName)
	}

	// VF NIC name
	vfDevName := infos[0].Name()
	vfDev, err := netlink.LinkByName(vfDevName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup vf device %q: %v", vfDevName, err)
	}

	if err = netlink.LinkSetVfHardwareAddr(m, vfIdx, bo.HardwareAddr); err != nil {
		return nil, fmt.Errorf("failed to set vf %d macaddress: %v", vfIdx, err)
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
		vfInterface.Name = ifName

		// Re-fetch macvlan to get all properties/attributes
		vf, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch vf %q: %v", ifName, err)
		}
		err = netlink.LinkSetMasterByIndex(vf, bo.Index)
        	if err != nil {
		        return fmt.Errorf("设置vf为bonding的slave失败: %v", err)
	        }
		vfInterface.Mac = bo.HardwareAddr.String()
		vfInterface.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return vfInterface, nil
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

func setupBond(n *NetConf, ifName string, netns ns.NetNS) (*netlink.Bond, *current.Interface, error) {
	bo := &netlink.Bond{}
	boInterface := &current.Interface{}

	var ok bool
	mv := &netlink.Bond{
		LinkAttrs: netlink.LinkAttrs{
			MTU:		1500,
			Name:		ifName,
			ParentIndex:	-1,
			Namespace:	netlink.NsFd(int(netns.Fd())),
		},
		Mode:	4,
		ActiveSlave:	-1,
		Miimon:		100,
		UpDelay:	-1,
		DownDelay:       -1,
		UseCarrier:      -1,
		ArpInterval:     -1,
		ArpIpTargets:    nil,
		ArpValidate:     -1,
		ArpAllTargets:   -1,
		Primary:         -1,
		PrimaryReselect: -1,
		FailOverMac:     1,
		XmitHashPolicy:  -1,
		ResendIgmp:      -1,
		NumPeerNotif:    -1,
		AllSlavesActive: -1,
		MinLinks:        0,
		LpInterval:      -1,
		PackersPerSlave: -1,
		LacpRate:        0,
		AdSelect:        0,
	}

	err := netns.Do(func(_ ns.NetNS) error {
		if err := netlink.LinkAdd(mv); err != nil {
			// return fmt.Errorf("failed to create bond: %v", err)
			return err
		}
		boInterface.Name = ifName

		// Re-fetch ipvlan to get all properties/attributes
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch bond %q: %v", ifName, err)
		}

		if err := netlink.LinkSetUp(l); err != nil {
	                return fmt.Errorf("failed to set %q UP: %v", ifName, err)
        	}


		boInterface.Mac = l.Attrs().HardwareAddr.String()
		boInterface.Sandbox = netns.Path()

		bo, ok = l.(*netlink.Bond)
		if !ok {
			return fmt.Errorf("%q already exists but is not a bridge", ifName)
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return bo, boInterface, nil
}

func createBondvlan(ifName string, bo *netlink.Bond, vlanId int, netns ns.NetNS) (*current.Interface, error) {
	bondvlan := &current.Interface{}

	// bondvlanName := fmt.Sprintf("%s.%d", bo.Name, vlanId)
	bondvlanName := ifName
	mv := &netlink.Vlan{
	        LinkAttrs: netlink.LinkAttrs{
	                MTU:            1500,
	                Name:           bondvlanName,
	                ParentIndex:    bo.Index,
	                Namespace:      netlink.NsFd(int(netns.Fd())),
			HardwareAddr:	bo.HardwareAddr,
	        },
	        VlanId: vlanId,
	}

	err := netns.Do(func(_ ns.NetNS) error {
		err := netlink.LinkAdd(mv)
		if err != nil {
			return fmt.Errorf("创建bond vlan失败: %v", err)
		}

		bondvlan.Name = mv.Name
		bondvlan.Mac = mv.Attrs().HardwareAddr.String()
		bondvlan.Sandbox = netns.Path()

		return nil
	})

	if err != nil {
		return nil, err
	}

	return bondvlan, nil
}

func ConfigureIface(ifName string, res *current.Result) error {
	if len(res.Interfaces) == 0 {
		return fmt.Errorf("no interfaces to configure")
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	var v4gw, v6gw net.IP
	for _, ipc := range res.IPs {
		if int(ipc.Interface) >= len(res.Interfaces) {
			// IP address is for a different interface
			return fmt.Errorf("failed to add IP addr %v to %q: invalid interface index", ipc, ifName)
		}

		if res.Interfaces[ipc.Interface].Name == ifName {

			addr := &netlink.Addr{IPNet: &ipc.Address, Label: ""}
			if err = netlink.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add IP addr %v to %q: %v", ipc, ifName, err)
			}

			gwIsV4 := ipc.Gateway.To4() != nil
			if gwIsV4 && v4gw == nil {
				v4gw = ipc.Gateway
			} else if !gwIsV4 && v6gw == nil {
				v6gw = ipc.Gateway
			}
		}
	}

	for _, r := range res.Routes {
		routeIsV4 := r.Dst.IP.To4() != nil
		gw := r.GW
		if gw == nil {
			if routeIsV4 && v4gw != nil {
				gw = v4gw
			} else if !routeIsV4 && v6gw != nil {
				gw = v6gw
			}
		}
		if err = ip.AddRoute(&r.Dst, gw, link); err != nil {
			// we skip over duplicate routes as we assume the first one wins
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%v via %v dev %v': %v", r.Dst, gw, ifName, err)
			}
		}
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

	bo, _, err := setupBond(n, "bond0", netns)
	if err != nil {
		return fmt.Errorf("创建bonding出现错误:%v", err)
	}

	_, err = setupVF("eno50", "vf1", bo, netns)
	if err != nil {
                return fmt.Errorf("获取可用VF1出现错误:%v", err)
        }

	_, err = setupVF("eno49", "vf2", bo, netns)
	if err != nil {
                return fmt.Errorf("获取可用VF2出现错误:%v", err)
        }


	bondVlan1, err := createBondvlan("eth0", bo, 1518, netns)
	if err != nil {
		return err
	}

	bondVlan2, err := createBondvlan("eth1", bo, 1519, netns)
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
	result.Interfaces = []*current.Interface{bondVlan1, bondVlan2}
	return fmt.Errorf("result: %v", result)

	ip, network, err := net.ParseCIDR("211.159.200.66/27")
	if err != nil {
		return fmt.Errorf("解析IP地址失败: %v", err)
	}

	address1 := &net.IPNet{IP:ip, Mask:network.Mask}
	ip1 := &current.IPConfig{Version:"4", Interface:0, Address:*address1, Gateway:net.ParseIP("211.159.200.65")}

	ip, network, err = net.ParseCIDR("10.20.99.2/24")
        if err != nil {
                return fmt.Errorf("解析IP地址失败2: %v", err)
        }

	address2 := &net.IPNet{IP:ip, Mask:network.Mask}
	ip2 := &current.IPConfig{Version:"4", Interface:1, Address:*address2, Gateway:net.ParseIP("10.20.99.1")}
	result.IPs = []*current.IPConfig{ip1, ip2}

	err = netns.Do(func(_ ns.NetNS) error {
	        return ConfigureIface("eth0", result)
	})
	if err != nil {
	        return fmt.Errorf("配置bondvlan 1518的地址出错: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
                return ConfigureIface("eth1", result)
        })
        if err != nil {
                return fmt.Errorf("配置bondvlan 1519的地址出错: %v", err)
        }

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
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
