# -*- encoding:utf-8 -*-
# auth:tomato
import ipaddress


def logo():
    print(r"/---------------------------------------------------\ ")
    print(r"|   作者          : tomato                           |")
    print(r"|   版本          : V1.0                             |")
    print(r"\---------------------------------------------------/")
    print(r" -----------------[请勿用于违法用途]------------------ ")
    print("\n")


def read_file_line_by_line(file_name):
    with open(file_name, "r", encoding="UTF-8") as file:
        for line in file:
            yield line.strip()


def parse_whitelist(src_lines):
    whitelist_ips = set()
    for line in src_lines:
        line = line.strip()
        if not line:
            continue  # 跳过空行
        try:
            if '/' in line:  # CIDR
                network = ipaddress.ip_network(line, strict=False)
                whitelist_ips.update(network)
            elif '-' in line:  # IP range
                start_ip, end_ip = line.split('-')
                start_ip = ipaddress.ip_address(start_ip.strip())
                if '.' not in end_ip:  # 简写的 IP
                    end_ip = f"{str(start_ip).rsplit('.', 1)[0]}.{end_ip.strip()}"
                end_ip = ipaddress.ip_address(end_ip.strip())
                for ip in range(int(start_ip), int(end_ip) + 1):
                    whitelist_ips.add(ipaddress.ip_address(ip))
            else:  # 单个IP
                whitelist_ips.add(ipaddress.ip_address(line))
        except ValueError as e:
            print(f"无效的白名单输入: {line} - 错误: {e}")
    return whitelist_ips


def check_duplicates(file_name):
    seen_ips = set()
    duplicates = set()
    for ip in read_file_line_by_line(file_name):
        ip = ip.strip()
        if ip:
            if ip in seen_ips:
                duplicates.add(ip)
            else:
                seen_ips.add(ip)
    return duplicates


def is_private_ip(ip):
    """判断给定 IP 是否是内网地址"""
    return ip.is_private


def main():
    src_file = "white.txt"
    dst_file = "black.txt"
    src_lines = read_file_line_by_line(src_file)
    whitelist_ips = parse_whitelist(src_lines)

    logo()

    # 1. 检查黑名单中的重复 IP
    duplicates = check_duplicates(dst_file)
    if duplicates:
        print("黑名单中存在重复的 IP：")
        for dup_ip in duplicates:
            print(f"[-] \033[31m{dup_ip}\033[0m")
    else:
        print("黑名单中没有重复的 IP。")

    matched_ips = []
    private_ips = []
    for blacklisted_ip in read_file_line_by_line(dst_file):
        blacklisted_ip = blacklisted_ip.strip()
        if blacklisted_ip:
            try:
                ip = ipaddress.ip_address(blacklisted_ip)

                # 2. 判断是否为内网 IP
                if is_private_ip(ip):
                    private_ips.append(blacklisted_ip)

                # 3. 判断是否在白名单中
                if ip in whitelist_ips:
                    matched_ips.append(blacklisted_ip)

            except ValueError:
                print(f"无效的黑名单输入: {blacklisted_ip} - 不是有效的 IP 地址。")

    # 输出结果
    if private_ips:
        print("\n以下 IP 属于内网地址：")
        for private_ip in private_ips:
            print(f"[-] \033[31m{private_ip}\033[0m (内网)")

    if matched_ips:
        print(f"\n对比已完成，总共匹配了 {len(matched_ips)} 个IP:")
        for idx, ip in enumerate(matched_ips, start=1):
            print(f"[-] 黑名单中的 \033[31m{ip}\033[0m 在白名单中 - 累计匹配数: {idx}")
    else:
        print("\n对比已完成，没有匹配的IP。")


if __name__ == '__main__':
    main()
