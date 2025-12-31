[RULE: ngfw_standalone]
alter
    _empty_ip = "00000000000000000000ffff00000000",
    _is_nat = to_boolean(is_nat),
    _is_proxy = to_boolean(is_proxy),
    _source_port = to_integer(source_port),
    _dest_port = to_integer(dest_port),
    _is_dest_ipv6 = if(dest_ip contains ":"),
    _is_source_ipv6 = if(source_ip contains ":"),
    _session_id = to_string(session_id)
| alter
    xdm.event.id = _session_id,
    xdm.event.operation_sub_type = sub_type,
    xdm.event.type = log_type,
    xdm.intermediate.ipv4 = if(_is_proxy = True and _is_dest_ipv6 = False and dest_ip != _empty_ip, dest_ip),
    xdm.intermediate.ipv6 = if(_is_proxy = True and _is_dest_ipv6 = True, dest_ip),
    xdm.intermediate.is_nat = _is_nat,
    xdm.intermediate.is_proxy = _is_proxy,
    xdm.intermediate.port = if(_is_proxy = True, _dest_port),
    xdm.network.application_protocol = app,
    xdm.network.application_protocol_category = app_category,
    xdm.network.application_protocol_subcategory = app_sub_category,
    xdm.network.ip_protocol = if(protocol="icmp", XDM_CONST.IP_PROTOCOL_ICMP, protocol="tcp", XDM_CONST.IP_PROTOCOL_TCP, protocol="udp", XDM_CONST.IP_PROTOCOL_UDP, protocol),
    xdm.network.rule = rule_matched,
    xdm.observer.action = action,
    xdm.observer.name = log_source_name,
    xdm.observer.type = log_source,
    xdm.observer.unique_identifier = log_source_id,
    xdm.session_context_id = _session_id,
    xdm.source.host.hostname = if(source_device_host not contains ":", source_device_host),
    xdm.source.host.device_category = source_device_category,
    xdm.source.host.device_id = source_device_mac,
    xdm.source.host.device_model = source_device_model,
    xdm.source.host.mac_addresses = if(source_device_mac != null, arraycreate(source_device_mac)),
    xdm.source.host.manufacturer = source_device_vendor,
    xdm.source.host.os = source_device_os,
    xdm.source.host.os_family = if(source_device_osfamily="Windows", XDM_CONST.OS_FAMILY_WINDOWS , source_device_osfamily in ("MacOS", "Mac"), XDM_CONST.OS_FAMILY_MACOS, source_device_osfamily in ("ios", "iOS"), XDM_CONST.OS_FAMILY_IOS, source_device_osfamily="Chromeos", XDM_CONST.OS_FAMILY_CHROMEOS, source_device_osfamily="Linux", XDM_CONST.OS_FAMILY_LINUX, source_device_osfamily="Android", XDM_CONST.OS_FAMILY_ANDROID, source_device_osfamily),
    xdm.source.interface = inbound_if,
    xdm.source.ipv4 = if(_is_source_ipv6 = False and source_ip != _empty_ip, source_ip),
    xdm.source.ipv6 = if(_is_source_ipv6 = True, source_ip),
    xdm.source.port = _source_port,
    xdm.source.user.username = source_user,
    xdm.source.zone = from_zone,
    xdm.target.host.hostname = if(dest_device_host not contains ":", dest_device_host),
    xdm.target.host.device_category = dest_device_category,
    xdm.target.host.device_id = dest_device_mac,
    xdm.target.host.device_model = dest_device_model,
    xdm.target.host.mac_addresses = if(dest_device_mac != null, arraycreate(dest_device_mac)),
    xdm.target.host.manufacturer = dest_device_vendor,
    xdm.target.host.os = dest_device_os,
    xdm.target.host.os_family = if(dest_device_osfamily="Windows", XDM_CONST.OS_FAMILY_WINDOWS , dest_device_osfamily in ("MacOS", "Mac"), XDM_CONST.OS_FAMILY_MACOS, dest_device_osfamily in ("ios", "iOS"), XDM_CONST.OS_FAMILY_IOS, dest_device_osfamily="Chromeos", XDM_CONST.OS_FAMILY_CHROMEOS, dest_device_osfamily="Linux", XDM_CONST.OS_FAMILY_LINUX, dest_device_osfamily="Android", XDM_CONST.OS_FAMILY_ANDROID, dest_device_osfamily),
    xdm.target.interface = outbound_if,
    xdm.target.ipv4 = if(_is_dest_ipv6 = False and dest_ip != _empty_ip, dest_ip),
    xdm.target.ipv6 = if(_is_dest_ipv6 = True, dest_ip),
    xdm.target.port = _dest_port,
    xdm.target.user.username = dest_user,
    xdm.target.zone = to_zone;

[RULE: url_threat_common_fields]
alter
    xdm.network.http.method = if(http_method = "get", XDM_CONST.HTTP_METHOD_GET, http_method = "post", XDM_CONST.HTTP_METHOD_POST, http_method = "connect", XDM_CONST.HTTP_METHOD_CONNECT, http_method = "head", XDM_CONST.HTTP_METHOD_HEAD, http_method = "put", XDM_CONST.HTTP_METHOD_PUT, http_method = "delete", XDM_CONST.HTTP_METHOD_DELETE, http_method = "options", XDM_CONST.HTTP_METHOD_OPTIONS, http_method);

[MODEL:dataset="panw_ngfw_threat_raw"]
call ngfw_standalone
| call url_threat_common_fields
| alter
        threat_category_lower = lowercase(threat_category)
| alter
    xdm.event.original_event_type = "threat",
    //xdm.network.http.url_category = url_category,
    xdm.network.http.url = if(file_sha_256 = null, file_name),
    xdm.source.host.fqdn = url_domain,
    xdm.target.file.filename = if(file_sha_256 != null, file_name),
    xdm.event.description = pcap,
    xdm.target.file.file_type = file_type,
    xdm.target.file.sha256 = file_sha_256,
    xdm.email.subject = subject_of_email,
    xdm.alert.original_threat_id = to_string(threat_id),
    xdm.alert.original_threat_name = threat_name,
    xdm.alert.category = if(threat_category_lower = "apk", XDM_CONST.THREAT_CATEGORY_APK, threat_category_lower = "dmg", XDM_CONST.THREAT_CATEGORY_DMG, threat_category_lower = "flash", XDM_CONST.THREAT_CATEGORY_FLASH, threat_category_lower = "java-class", XDM_CONST.THREAT_CATEGORY_JAVA_CLASS, threat_category_lower = "macho", XDM_CONST.THREAT_CATEGORY_MACHO, threat_category_lower = "office", XDM_CONST.THREAT_CATEGORY_OFFICE, threat_category_lower = "openoffice", XDM_CONST.THREAT_CATEGORY_OPENOFFICE, threat_category_lower = "pdf", XDM_CONST.THREAT_CATEGORY_PDF, threat_category_lower = "pe", XDM_CONST.THREAT_CATEGORY_PE, threat_category_lower = "pkg", XDM_CONST.THREAT_CATEGORY_PKG, threat_category_lower = "adware", XDM_CONST.THREAT_CATEGORY_ADWARE, threat_category_lower = "autogen", XDM_CONST.THREAT_CATEGORY_AUTOGEN, threat_category_lower = "backdoor", XDM_CONST.THREAT_CATEGORY_BACKDOOR, threat_category_lower = "botnet", XDM_CONST.THREAT_CATEGORY_BOTNET, threat_category_lower = "browser-hijack", XDM_CONST.THREAT_CATEGORY_BROWSER_HIJACK, threat_category_lower = "cryptominer", XDM_CONST.THREAT_CATEGORY_CRYPTOMINER, threat_category_lower = "data-theft", XDM_CONST.THREAT_CATEGORY_DATA_THEFT, threat_category_lower = "dns", XDM_CONST.THREAT_CATEGORY_DNS, threat_category_lower = "dns-security", XDM_CONST.THREAT_CATEGORY_DNS_SECURITY, threat_category_lower = "dns-wildfire", XDM_CONST.THREAT_CATEGORY_DNS_WILDFIRE, threat_category_lower = "downloader", XDM_CONST.THREAT_CATEGORY_DOWNLOADER, threat_category_lower = "fraud", XDM_CONST.THREAT_CATEGORY_FRAUD, threat_category_lower = "hacktool", XDM_CONST.THREAT_CATEGORY_HACKTOOL, threat_category_lower = "keylogger", XDM_CONST.THREAT_CATEGORY_KEYLOGGER, threat_category_lower = "networm", XDM_CONST.THREAT_CATEGORY_NETWORM, threat_category_lower = "phishing-kit", XDM_CONST.THREAT_CATEGORY_PHISHING_KIT, threat_category_lower = "post-exploitation", XDM_CONST.THREAT_CATEGORY_POST_EXPLOITATION, threat_category_lower = "webshell", XDM_CONST.THREAT_CATEGORY_WEBSHELL, threat_category_lower = "spyware", XDM_CONST.THREAT_CATEGORY_SPYWARE, threat_category_lower = "brute force", XDM_CONST.THREAT_CATEGORY_BRUTE_FORCE, threat_category_lower = "code execution", XDM_CONST.THREAT_CATEGORY_CODE_EXECUTION, threat_category_lower = "code-obfuscation", XDM_CONST.THREAT_CATEGORY_CODE_OBFUSCATION, threat_category_lower = "dos", XDM_CONST.THREAT_CATEGORY_DOS, threat_category_lower = "exploit-kit", XDM_CONST.THREAT_CATEGORY_EXPLOIT_KIT, threat_category_lower = "info-leak", XDM_CONST.THREAT_CATEGORY_INFO_LEAK, threat_category_lower = "insecure-credentials", XDM_CONST.THREAT_CATEGORY_INSECURE_CREDENTIALS, threat_category_lower = "overflow", XDM_CONST.THREAT_CATEGORY_OVERFLOW, threat_category_lower = "phishing", XDM_CONST.THREAT_CATEGORY_PHISHING, threat_category_lower = "protocol-anomaly", XDM_CONST.THREAT_CATEGORY_PROTOCOL_ANOMALY, threat_category_lower = "sql-injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION, to_string(threat_category)),
    xdm.alert.severity = severity,
    xdm.alert.description = verdict;

[MODEL: dataset=corelight_http_raw]
filter _path ~= "dns"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.observer.name = _system_name, 
    xdm.observer.version = version,
    xdm.event.type = _path,
    xdm.event.id = uid,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)), 
    xdm.event.duration = to_integer(rtt), 
    xdm.network.dns.is_response = to_boolean(rejected),
    xdm.event.description = payload_printable, 
    xdm.network.dns.dns_question.name = query,
    xdm.network.dns.dns_question.type = if(qtype_name="A",XDM_CONST.DNS_RECORD_TYPE_A, qtype_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, qtype_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, qtype_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, qtype_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, qtype_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, qtype_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, qtype_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, qtype_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, qtype_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, qtype_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, qtype_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, qtype_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, qtype_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, qtype_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, qtype_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, qtype_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, qtype_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, qtype_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, qtype_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, qtype_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, qtype_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, qtype_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, qtype_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, qtype_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, qtype_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, qtype_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, qtype_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, qtype_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, qtype_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, qtype_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, qtype_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, qtype_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, qtype_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, qtype_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, qtype_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, qtype_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, qtype_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, qtype_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, qtype_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, qtype_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, qtype_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, qtype_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, qtype_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, qtype_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, qtype_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, qtype_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(qtype_name)),
    xdm.network.dns.dns_resource_record.name = to_string(rcode),
    xdm.network.dns.dns_resource_record.type = if(rcode_name="A",XDM_CONST.DNS_RECORD_TYPE_A, rcode_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, rcode_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, rcode_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, rcode_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, rcode_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, rcode_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, rcode_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, rcode_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, rcode_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, rcode_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, rcode_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, rcode_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, rcode_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, rcode_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, rcode_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, rcode_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, rcode_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, rcode_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, rcode_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, rcode_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, rcode_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, rcode_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, rcode_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, rcode_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, rcode_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, rcode_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, rcode_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, rcode_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, rcode_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, rcode_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, rcode_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, rcode_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, rcode_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, rcode_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, rcode_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, rcode_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, rcode_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, rcode_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, rcode_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, rcode_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, rcode_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, rcode_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, rcode_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, rcode_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, rcode_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, rcode_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(rcode_name)),
    xdm.source.agent.identifier = trans_id,
    xdm.network.dns.dns_resource_record.value = answers;
// HTTP Logs
filter _path ~= "http"
| alter
    status_code_string = to_string(status_code)
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.name = _system_name,
    xdm.observer.version = version,
    xdm.event.id = uid,
    xdm.network.http.referrer = referrer,
    xdm.network.http.url = uri,
    xdm.observer.unique_identifier = tags,
    xdm.source.user_agent = user_agent,
    xdm.network.http.method = if(method = "ACL", XDM_CONST.HTTP_METHOD_ACL, method = "BASELINE_CONTROL", XDM_CONST.HTTP_METHOD_BASELINE_CONTROL , method = "BIND", XDM_CONST.HTTP_METHOD_BIND, method = "CHECKIN", XDM_CONST.HTTP_METHOD_CHECKIN, method = "CHECKOUT", XDM_CONST.HTTP_METHOD_CHECKOUT, method = "CONNECT", XDM_CONST.HTTP_METHOD_CONNECT, method = "COPY", XDM_CONST.HTTP_METHOD_COPY, method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE, method = "GET", XDM_CONST.HTTP_METHOD_GET, method = "HEAD", XDM_CONST.HTTP_METHOD_HEAD, method = "LABEL", XDM_CONST.HTTP_METHOD_LABEL, method = "LINK", XDM_CONST.HTTP_METHOD_LINK, method = "LOCK", XDM_CONST.HTTP_METHOD_LOCK, method = "MERGE", XDM_CONST.HTTP_METHOD_MERGE, method = "MKACTIVITY", XDM_CONST.HTTP_METHOD_MKACTIVITY, method = "MKCALENDAR", XDM_CONST.HTTP_METHOD_MKCALENDAR, method = "MKCOL", XDM_CONST.HTTP_METHOD_MKCOL, method = "MKREDIRECTREF", XDM_CONST.HTTP_METHOD_MKREDIRECTREF, method = "MKWORKSPACE", XDM_CONST.HTTP_METHOD_MKWORKSPACE, method = "MOVE", XDM_CONST.HTTP_METHOD_MOVE, method = "OPTIONS", XDM_CONST.HTTP_METHOD_OPTIONS, method = "ORDERPATCH", XDM_CONST.HTTP_METHOD_ORDERPATCH, method = "PATCH", XDM_CONST.HTTP_METHOD_PATCH, method = "POST", XDM_CONST.HTTP_METHOD_POST, method = "PRI", XDM_CONST.HTTP_METHOD_PRI, method = "PROPFIND", XDM_CONST.HTTP_METHOD_PROPFIND, method = "PROPPATCH", XDM_CONST.HTTP_METHOD_PROPPATCH, method = "PUT", XDM_CONST.HTTP_METHOD_PUT, method = "REBIND", XDM_CONST.HTTP_METHOD_REBIND, method = "REPORT", XDM_CONST.HTTP_METHOD_REPORT, method = "SEARCH", XDM_CONST.HTTP_METHOD_SEARCH, method = "TRACE", XDM_CONST.HTTP_METHOD_TRACE, method = "UNBIND", XDM_CONST.HTTP_METHOD_UNBIND, method = "UNCHECKOUT", XDM_CONST.HTTP_METHOD_UNCHECKOUT, method = "UNLINK", XDM_CONST.HTTP_METHOD_UNLINK, method = "UNLOCK", XDM_CONST.HTTP_METHOD_UNLOCK, method = "UPDATE", XDM_CONST.HTTP_METHOD_UPDATE, method = "UPDATEREDIRECTREF", XDM_CONST.HTTP_METHOD_UPDATEREDIRECTREF, method = "VERSION_CONTROL", XDM_CONST.HTTP_METHOD_VERSION_CONTROL, method = null, null, to_string(method)),
    xdm.event.description = payload_printable, 
    xdm.network.http.response_code = if(status_code_string = "100", XDM_CONST.HTTP_RSP_CODE_CONTINUE, status_code_string = "101", XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS, status_code_string = "102", XDM_CONST.HTTP_RSP_CODE_PROCESSING, status_code_string = "103", XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS, status_code_string = "200", XDM_CONST.HTTP_RSP_CODE_OK, status_code_string = "201", XDM_CONST.HTTP_RSP_CODE_CREATED, status_code_string = "202", XDM_CONST.HTTP_RSP_CODE_ACCEPTED, status_code_string = "203", XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION, status_code_string = "204", XDM_CONST.HTTP_RSP_CODE_NO_CONTENT, status_code_string = "205", XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT, status_code_string = "206", XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT, status_code_string = "207", XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS, status_code_string = "208", XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED, status_code_string = "226", XDM_CONST.HTTP_RSP_CODE_IM_USED, status_code_string = "300", XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES, status_code_string = "301", XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY, status_code_string = "302", XDM_CONST.HTTP_RSP_CODE_FOUND, status_code_string = "303", XDM_CONST.HTTP_RSP_CODE_SEE_OTHER, status_code_string = "304", XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED, status_code_string = "305", XDM_CONST.HTTP_RSP_CODE_USE_PROXY, status_code_string = "307", XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT, status_code_string = "308", XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT, status_code_string = "400", XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST, status_code_string = "401", XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED, status_code_string = "402", XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED, status_code_string = "403", XDM_CONST.HTTP_RSP_CODE_FORBIDDEN, status_code_string = "404", XDM_CONST.HTTP_RSP_CODE_NOT_FOUND, status_code_string = "405", XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED, status_code_string = "406", XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE, status_code_string = "407", XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED, status_code_string = "408", XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT, status_code_string = "409", XDM_CONST.HTTP_RSP_CODE_CONFLICT, status_code_string = "410", XDM_CONST.HTTP_RSP_CODE_GONE, status_code_string = "411", XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED, status_code_string = "412", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED, status_code_string = "413", XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE, status_code_string = "414", XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG, status_code_string = "415", XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE, status_code_string = "416", XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE, status_code_string = "417", XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED, status_code_string = "421", XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST, status_code_string = "422", XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT, status_code_string = "423", XDM_CONST.HTTP_RSP_CODE_LOCKED, status_code_string = "424", XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY, status_code_string = "425", XDM_CONST.HTTP_RSP_CODE_TOO_EARLY, status_code_string = "426", XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED, status_code_string = "428", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED, status_code_string = "429", XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS, status_code_string = "431", XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE, status_code_string = "451", XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS, status_code_string = "500", XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR, status_code_string = "501", XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED, status_code_string = "502", XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY, status_code_string = "503", XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE, status_code_string = "504", XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT, status_code_string = "505", XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED, status_code_string = "506", XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES, status_code_string = "507", XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE, status_code_string = "508", XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED, status_code_string = "511", XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED, status_code_string = null, null, to_string(status_code_string)),
    xdm.source.host.hostname = origin,
    xdm.source.sent_bytes = to_integer(request_body_len),
    xdm.target.host.hostname = host,
    xdm.target.sent_bytes = to_integer(response_body_len);
// NTLM Logs
filter _path ~= "ntlm"
| alter str_scuccess = to_string(success)
 | alter 
     xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
     xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
     xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
     xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
     xdm.source.port = to_integer(id_orig_p),
     xdm.target.port = to_integer(id_resp_p),
     xdm.event.type = _path,
     xdm.observer.version = version,
     xdm.observer.name = _system_name,
     xdm.event.id = uid,
     xdm.auth.ntlm.user_name = username,
     xdm.auth.ntlm.hostname = hostname,
     xdm.auth.ntlm.domain = domainname,
     xdm.auth.ntlm.dns_domain = server_dns_computer_name,
     xdm.auth.ntlm.dns_three = server_tree_name,
     xdm.event.description = payload_printable,    
     xdm.event.outcome = if(str_scuccess = "true", XDM_CONST.OUTCOME_SUCCESS, str_scuccess = "false", XDM_CONST.OUTCOME_FAILED, str_scuccess = null, null, "UNKNOWN");
// Syslogs 
filter _path ~= "syslog"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.description = message,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)),
    xdm.alert.severity = severity,
    xdm.intermediate.process.name = facility;
// Conn Logs
filter _path ~= "conn"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.source.host.device_id = id_orig_l2_addr,
    xdm.target.host.device_id = id_resp_l2_addr, 
    xdm.event.id = uid,
    xdm.event.operation_sub_type = conn_state,
    xdm.network.application_protocol = service,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)),
    xdm.event.duration = to_integer(multiply(to_float(duration), 1000)),
    xdm.source.sent_bytes = to_integer(orig_bytes),
    xdm.source.sent_packets = to_integer(orig_pkts),
    xdm.target.sent_bytes = to_integer(resp_bytes),
    xdm.target.sent_packets = to_integer(resp_pkts)
| alter xdm.event.outcome = if(proto = "tcp" and to_integer(resp_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "tcp" and to_integer(resp_pkts) = 0, XDM_CONST.OUTCOME_FAILED, proto = "icmp" and to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "icmp" and to_integer(resp_pkts) = 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_FAILED, to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0 and to_integer(resp_bytes) > 0 and to_integer(orig_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, null);
// Kerberos
filter _path ~= "kerberos"
| alter
   lower_c_cipher = lowercase(cipher) 
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.outcome = if(success = "true", XDM_CONST.OUTCOME_SUCCESS, success = "false", XDM_CONST.OUTCOME_FAILED , success = null, null, to_string(success)),
    xdm.auth.kerberos_tgt.msg_type = if(request_type = "AS", XDM_CONST.KERBEROS_MSG_TYPE_AS_REQ, request_type = "TGS", XDM_CONST.KERBEROS_MSG_TYPE_TGS_REQ, request_type = "AP", XDM_CONST.KERBEROS_MSG_TYPE_AP_REQ, request_type = "RESERVED16", XDM_CONST.KERBEROS_MSG_TYPE_RESERVED16, request_type = "SAFE", XDM_CONST.KERBEROS_MSG_TYPE_SAFE, request_type = "PRIV", XDM_CONST.KERBEROS_MSG_TYPE_PRIV, request_type = "CRED", XDM_CONST.KERBEROS_MSG_TYPE_CRED, request_type = "ERROR", XDM_CONST.KERBEROS_MSG_TYPE_ERROR, request_type = null, null, to_string(request_type)),    
    xdm.auth.kerberos_tgt.spn_values = arraycreate(service),
    xdm.auth.kerberos_tgt.cname_values = arraycreate(client),
    xdm.auth.kerberos_tgt.encryption_type = if(lower_c_cipher ~= "des[\-|\_]cbc[\-|\_]crc", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_CRC, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha256[\_|\-]128", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha384[\_|\-]192", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA384_192, lower_c_cipher ~= "camellia128[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA128_CTS_CMAC, lower_c_cipher ~= "camellia256[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA256_CTS_CMAC, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_MD5, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_RAW, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1[\_|\-]kd", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1_KD, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md4", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD4, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD5, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_RAW, lower_c_cipher ~= "des[\_|\-]ede3[\_|\-]cbc[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_EDE3_CBC_ENV_OID, lower_c_cipher ~= "des[\_|\-]hmac[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_HMAC_SHA1, lower_c_cipher ~= "dsawithsha1[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DSAWITHSHA1_CMSOID, lower_c_cipher ~= "md5withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_MD5WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "rc2cbc[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC2CBC_ENVOID, lower_c_cipher ~= "rc4[\_|\-]hmac[\_|\-]exp", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC_EXP, lower_c_cipher ~= "rc4[\_|\-]hmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC, lower_c_cipher ~= "rsaencryption[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAENCRYPTION_ENVOID, lower_c_cipher ~= "rsaes[\_|\-]oaep[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAES_OAEP_ENV_OID, lower_c_cipher ~= "sha1withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SHA1WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "subkey[\_|\-]keymaterial", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SUBKEY_KEYMATERIAL, to_string(lower_c_cipher));
// // DCE_RPC
// filter _path ~= "dce_rpc"
// | alter
//     xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
//     xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
//     xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
//     xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
//     xdm.source.port = to_integer(id_orig_p),
//     xdm.target.port = to_integer(id_resp_p),
//     xdm.event.type = _path,
//     xdm.observer.name = _system_name,
//     xdm.event.id = uid,
//     xdm.event.duration = to_integer(rtt),
//     xdm.intermediate.application.name = named_pipe,
//     xdm.source.user.identifier = endpoint,
//     xdm.event.outcome_reason = operation,
//     xdm.observer.version = version;
// Suricata Corelight
filter _path ~= "suricata_corelight"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.observer.name = _system_name, 
    xdm.observer.version = version,
    xdm.event.type = _path,
    xdm.event.id = uid,
    xdm.event.description = payload_printable;

[MODEL: dataset=corelight_zeek_raw]
// DNS Logs
filter _path ~= "dns"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.observer.name = _system_name, 
    xdm.observer.version = version,
    xdm.event.type = _path,
    xdm.event.id = uid,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)), 
    xdm.event.duration = to_integer(rtt),
    xdm.network.dns.is_response = to_boolean(rejected),
    xdm.network.dns.dns_question.name = query,
    xdm.network.dns.dns_question.type = if(qtype_name="A",XDM_CONST.DNS_RECORD_TYPE_A, qtype_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, qtype_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, qtype_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, qtype_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, qtype_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, qtype_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, qtype_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, qtype_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, qtype_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, qtype_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, qtype_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, qtype_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, qtype_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, qtype_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, qtype_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, qtype_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, qtype_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, qtype_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, qtype_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, qtype_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, qtype_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, qtype_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, qtype_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, qtype_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, qtype_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, qtype_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, qtype_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, qtype_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, qtype_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, qtype_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, qtype_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, qtype_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, qtype_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, qtype_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, qtype_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, qtype_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, qtype_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, qtype_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, qtype_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, qtype_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, qtype_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, qtype_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, qtype_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, qtype_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, qtype_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, qtype_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(qtype_name)),
    xdm.network.dns.dns_resource_record.name = to_string(rcode),
    xdm.network.dns.dns_resource_record.type = if(rcode_name="A",XDM_CONST.DNS_RECORD_TYPE_A, rcode_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, rcode_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, rcode_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, rcode_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, rcode_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, rcode_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, rcode_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, rcode_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, rcode_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, rcode_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, rcode_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, rcode_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, rcode_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, rcode_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, rcode_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, rcode_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, rcode_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, rcode_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, rcode_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, rcode_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, rcode_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, rcode_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, rcode_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, rcode_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, rcode_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, rcode_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, rcode_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, rcode_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, rcode_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, rcode_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, rcode_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, rcode_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, rcode_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, rcode_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, rcode_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, rcode_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, rcode_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, rcode_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, rcode_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, rcode_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, rcode_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, rcode_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, rcode_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, rcode_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, rcode_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, rcode_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(rcode_name)),
    xdm.source.agent.identifier = trans_id,
    xdm.network.dns.dns_resource_record.value = answers;
// HTTP Logs
filter _path ~= "http"
| alter
    status_code_string = to_string(status_code)
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.name = _system_name,
    xdm.observer.version = version,
    xdm.event.id = uid,
    xdm.network.http.referrer = referrer,
    xdm.network.http.url = uri,
    xdm.observer.unique_identifier = tags,
    xdm.source.user_agent = user_agent,
    xdm.network.http.method = if(method = "ACL", XDM_CONST.HTTP_METHOD_ACL, method = "BASELINE_CONTROL", XDM_CONST.HTTP_METHOD_BASELINE_CONTROL , method = "BIND", XDM_CONST.HTTP_METHOD_BIND, method = "CHECKIN", XDM_CONST.HTTP_METHOD_CHECKIN, method = "CHECKOUT", XDM_CONST.HTTP_METHOD_CHECKOUT, method = "CONNECT", XDM_CONST.HTTP_METHOD_CONNECT, method = "COPY", XDM_CONST.HTTP_METHOD_COPY, method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE, method = "GET", XDM_CONST.HTTP_METHOD_GET, method = "HEAD", XDM_CONST.HTTP_METHOD_HEAD, method = "LABEL", XDM_CONST.HTTP_METHOD_LABEL, method = "LINK", XDM_CONST.HTTP_METHOD_LINK, method = "LOCK", XDM_CONST.HTTP_METHOD_LOCK, method = "MERGE", XDM_CONST.HTTP_METHOD_MERGE, method = "MKACTIVITY", XDM_CONST.HTTP_METHOD_MKACTIVITY, method = "MKCALENDAR", XDM_CONST.HTTP_METHOD_MKCALENDAR, method = "MKCOL", XDM_CONST.HTTP_METHOD_MKCOL, method = "MKREDIRECTREF", XDM_CONST.HTTP_METHOD_MKREDIRECTREF, method = "MKWORKSPACE", XDM_CONST.HTTP_METHOD_MKWORKSPACE, method = "MOVE", XDM_CONST.HTTP_METHOD_MOVE, method = "OPTIONS", XDM_CONST.HTTP_METHOD_OPTIONS, method = "ORDERPATCH", XDM_CONST.HTTP_METHOD_ORDERPATCH, method = "PATCH", XDM_CONST.HTTP_METHOD_PATCH, method = "POST", XDM_CONST.HTTP_METHOD_POST, method = "PRI", XDM_CONST.HTTP_METHOD_PRI, method = "PROPFIND", XDM_CONST.HTTP_METHOD_PROPFIND, method = "PROPPATCH", XDM_CONST.HTTP_METHOD_PROPPATCH, method = "PUT", XDM_CONST.HTTP_METHOD_PUT, method = "REBIND", XDM_CONST.HTTP_METHOD_REBIND, method = "REPORT", XDM_CONST.HTTP_METHOD_REPORT, method = "SEARCH", XDM_CONST.HTTP_METHOD_SEARCH, method = "TRACE", XDM_CONST.HTTP_METHOD_TRACE, method = "UNBIND", XDM_CONST.HTTP_METHOD_UNBIND, method = "UNCHECKOUT", XDM_CONST.HTTP_METHOD_UNCHECKOUT, method = "UNLINK", XDM_CONST.HTTP_METHOD_UNLINK, method = "UNLOCK", XDM_CONST.HTTP_METHOD_UNLOCK, method = "UPDATE", XDM_CONST.HTTP_METHOD_UPDATE, method = "UPDATEREDIRECTREF", XDM_CONST.HTTP_METHOD_UPDATEREDIRECTREF, method = "VERSION_CONTROL", XDM_CONST.HTTP_METHOD_VERSION_CONTROL, method = null, null, to_string(method)),
    xdm.network.http.response_code = if(status_code_string = "100", XDM_CONST.HTTP_RSP_CODE_CONTINUE, status_code_string = "101", XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS, status_code_string = "102", XDM_CONST.HTTP_RSP_CODE_PROCESSING, status_code_string = "103", XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS, status_code_string = "200", XDM_CONST.HTTP_RSP_CODE_OK, status_code_string = "201", XDM_CONST.HTTP_RSP_CODE_CREATED, status_code_string = "202", XDM_CONST.HTTP_RSP_CODE_ACCEPTED, status_code_string = "203", XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION, status_code_string = "204", XDM_CONST.HTTP_RSP_CODE_NO_CONTENT, status_code_string = "205", XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT, status_code_string = "206", XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT, status_code_string = "207", XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS, status_code_string = "208", XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED, status_code_string = "226", XDM_CONST.HTTP_RSP_CODE_IM_USED, status_code_string = "300", XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES, status_code_string = "301", XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY, status_code_string = "302", XDM_CONST.HTTP_RSP_CODE_FOUND, status_code_string = "303", XDM_CONST.HTTP_RSP_CODE_SEE_OTHER, status_code_string = "304", XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED, status_code_string = "305", XDM_CONST.HTTP_RSP_CODE_USE_PROXY, status_code_string = "307", XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT, status_code_string = "308", XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT, status_code_string = "400", XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST, status_code_string = "401", XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED, status_code_string = "402", XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED, status_code_string = "403", XDM_CONST.HTTP_RSP_CODE_FORBIDDEN, status_code_string = "404", XDM_CONST.HTTP_RSP_CODE_NOT_FOUND, status_code_string = "405", XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED, status_code_string = "406", XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE, status_code_string = "407", XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED, status_code_string = "408", XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT, status_code_string = "409", XDM_CONST.HTTP_RSP_CODE_CONFLICT, status_code_string = "410", XDM_CONST.HTTP_RSP_CODE_GONE, status_code_string = "411", XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED, status_code_string = "412", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED, status_code_string = "413", XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE, status_code_string = "414", XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG, status_code_string = "415", XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE, status_code_string = "416", XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE, status_code_string = "417", XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED, status_code_string = "421", XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST, status_code_string = "422", XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT, status_code_string = "423", XDM_CONST.HTTP_RSP_CODE_LOCKED, status_code_string = "424", XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY, status_code_string = "425", XDM_CONST.HTTP_RSP_CODE_TOO_EARLY, status_code_string = "426", XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED, status_code_string = "428", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED, status_code_string = "429", XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS, status_code_string = "431", XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE, status_code_string = "451", XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS, status_code_string = "500", XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR, status_code_string = "501", XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED, status_code_string = "502", XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY, status_code_string = "503", XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE, status_code_string = "504", XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT, status_code_string = "505", XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED, status_code_string = "506", XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES, status_code_string = "507", XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE, status_code_string = "508", XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED, status_code_string = "511", XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED, status_code_string = null, null, to_string(status_code_string)),
    xdm.source.host.hostname = origin,
    xdm.source.sent_bytes = to_integer(request_body_len),
    xdm.target.host.hostname = host,
    xdm.target.sent_bytes = to_integer(response_body_len);
// NTLM Logs
// Syslogs 
filter _path ~= "syslog"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.description = message,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)),
    xdm.alert.severity = severity,
    xdm.intermediate.process.name = facility;
// Conn Logs
filter _path ~= "conn"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.source.host.device_id = id_orig_l2_addr,
    xdm.target.host.device_id = id_resp_l2_addr, 
    xdm.event.id = uid,
    xdm.event.operation_sub_type = conn_state,
    xdm.network.application_protocol = service,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)), 
    xdm.event.duration = to_integer(multiply(to_float(duration), 1000)),
    xdm.source.sent_bytes = to_integer(orig_bytes),
    xdm.source.sent_packets = to_integer(orig_pkts),
    xdm.target.sent_bytes = to_integer(resp_bytes),
    xdm.target.sent_packets = to_integer(resp_pkts)
| alter
    xdm.event.outcome = if(proto = "tcp" and to_integer(resp_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "tcp" and to_integer(resp_pkts) = 0, XDM_CONST.OUTCOME_FAILED, proto = "icmp" and to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "icmp" and to_integer(resp_pkts) = 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_FAILED, to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0 and to_integer(resp_bytes) > 0 and to_integer(orig_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, null);
// Kerberos
filter _path ~= "kerberos"
| alter
   lower_c_cipher = lowercase(cipher) 
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.outcome = if(success = true, XDM_CONST.OUTCOME_SUCCESS, success = false, XDM_CONST.OUTCOME_FAILED , success = null, null, to_string(success)),
    xdm.auth.kerberos_tgt.msg_type = if(request_type = "AS", XDM_CONST.KERBEROS_MSG_TYPE_AS_REQ, request_type = "TGS", XDM_CONST.KERBEROS_MSG_TYPE_TGS_REQ, request_type = "AP", XDM_CONST.KERBEROS_MSG_TYPE_AP_REQ, request_type = "RESERVED16", XDM_CONST.KERBEROS_MSG_TYPE_RESERVED16, request_type = "SAFE", XDM_CONST.KERBEROS_MSG_TYPE_SAFE, request_type = "PRIV", XDM_CONST.KERBEROS_MSG_TYPE_PRIV, request_type = "CRED", XDM_CONST.KERBEROS_MSG_TYPE_CRED, request_type = "ERROR", XDM_CONST.KERBEROS_MSG_TYPE_ERROR, request_type = null, null, to_string(request_type)),    
    xdm.auth.kerberos_tgt.spn_values = arraycreate(service),
    xdm.auth.kerberos_tgt.cname_values = arraycreate(client),
    xdm.auth.kerberos_tgt.encryption_type = if(lower_c_cipher ~= "des[\-|\_]cbc[\-|\_]crc", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_CRC, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha256[\_|\-]128", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha384[\_|\-]192", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA384_192, lower_c_cipher ~= "camellia128[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA128_CTS_CMAC, lower_c_cipher ~= "camellia256[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA256_CTS_CMAC, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_MD5, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_RAW, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1[\_|\-]kd", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1_KD, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md4", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD4, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD5, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_RAW, lower_c_cipher ~= "des[\_|\-]ede3[\_|\-]cbc[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_EDE3_CBC_ENV_OID, lower_c_cipher ~= "des[\_|\-]hmac[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_HMAC_SHA1, lower_c_cipher ~= "dsawithsha1[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DSAWITHSHA1_CMSOID, lower_c_cipher ~= "md5withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_MD5WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "rc2cbc[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC2CBC_ENVOID, lower_c_cipher ~= "rc4[\_|\-]hmac[\_|\-]exp", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC_EXP, lower_c_cipher ~= "rc4[\_|\-]hmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC, lower_c_cipher ~= "rsaencryption[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAENCRYPTION_ENVOID, lower_c_cipher ~= "rsaes[\_|\-]oaep[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAES_OAEP_ENV_OID, lower_c_cipher ~= "sha1withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SHA1WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "subkey[\_|\-]keymaterial", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SUBKEY_KEYMATERIAL, to_string(lower_c_cipher));
// DCE_RPC
filter _path ~= "dce_rpc"
| alter
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.duration = to_integer(rtt),
    xdm.intermediate.application.name = named_pipe,
    xdm.source.user.identifier = endpoint,
    xdm.event.outcome_reason = operation,
    xdm.observer.version = version;


[MODEL: dataset = cisco_umbrella_raw] //Fix to the DM for DNS logs NOTE THAT PROXY AND AUDIT WAS REMOVED

filter logType = "DNS"	
| alter	
xdm.event.type = logType,	
xdm.source.host.hostname = identity,	
xdm.source.ipv4 = internal_ip,	
xdm.source.ipv6 = internal_ip,	
xdm.intermediate.ipv4 = external_ip,	
xdm.intermediate.ipv6 = external_ip,	
xdm.observer.action = action,	
xdm.network.dns.dns_question.type = if (query_type = "A",XDM_CONST.DNS_RECORD_TYPE_A, Query_Type = "AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, Query_Type = "AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, Query_Type = "APL",XDM_CONST.DNS_RECORD_TYPE_APL, Query_Type = "CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, Query_Type = "CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, Query_Type = "CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, Query_Type = "CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, Query_Type = "CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, Query_Type = "CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, Query_Type = "DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, Query_Type = "DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, Query_Type = "DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, Query_Type = "DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, Query_Type = "DS",XDM_CONST.DNS_RECORD_TYPE_DS, Query_Type = "EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, Query_Type = "EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, Query_Type = "HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, Query_Type = "HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, Query_Type = "HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, Query_Type = "IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, Query_Type = "KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, Query_Type = "KX",XDM_CONST.DNS_RECORD_TYPE_KX, Query_Type = "LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, Query_Type = "MX",XDM_CONST.DNS_RECORD_TYPE_MX, Query_Type = "NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, Query_Type = "NS",XDM_CONST.DNS_RECORD_TYPE_NS, Query_Type = "NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, Query_Type = "NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, Query_Type = "NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, Query_Type = "OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, Query_Type = "PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, Query_Type = "RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, Query_Type = "RP",XDM_CONST.DNS_RECORD_TYPE_RP, Query_Type = "SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, Query_Type = "SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, Query_Type = "SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, Query_Type = "SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, Query_Type = "SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, Query_Type = "SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, Query_Type = "TA",XDM_CONST.DNS_RECORD_TYPE_TA, Query_Type = "TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, Query_Type = "TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, Query_Type = "TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, Query_Type = "TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, Query_Type = "URI",XDM_CONST.DNS_RECORD_TYPE_URI, Query_Type = "ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(Query_Type)),	
xdm.network.dns.response_code = if(Response_Code = "NOERROR",XDM_CONST.DNS_RESPONSE_CODE_NO_ERROR ,Response_Code = "FORMERR",XDM_CONST.DNS_RESPONSE_CODE_FORMAT_ERROR,Response_Code = "SERVFAIL",XDM_CONST.DNS_RESPONSE_CODE_SERVER_FAILURE,Response_Code = "NXDOMAIN",XDM_CONST.DNS_RESPONSE_CODE_NON_EXISTENT_DOMAIN,Response_Code = "NOTIMP",XDM_CONST.DNS_RESPONSE_CODE_NOT_IMPLEMENTED,Response_Code = "REFUSED",XDM_CONST.DNS_RESPONSE_CODE_QUERY_REFUSED,Response_Code = "YXDOMAIN",XDM_CONST.DNS_RESPONSE_CODE_NAME_EXISTS_WHEN_IT_SHOULD_NOT,Response_Code = "YXRRSET",XDM_CONST.DNS_RESPONSE_CODE_RR_SET_EXISTS_WHEN_IT_SHOULD_NOT,Response_Code = "NXRRSET",XDM_CONST.DNS_RESPONSE_CODE_RR_SET_THAT_SHOULD_EXIST_DOES_NOT,Response_Code = "NOTAUTH",XDM_CONST.DNS_RESPONSE_CODE_SERVER_NOT_AUTHORITATIVE_FOR_ZONE,Response_Code = "NOTZONE",XDM_CONST.DNS_RESPONSE_CODE_NAME_NOT_CONTAINED_IN_ZONE,Response_Code = "BADVERS",XDM_CONST.DNS_RESPONSE_CODE_BAD_OPT_VERSION,Response_Code = "BADSIG",XDM_CONST.DNS_RESPONSE_CODE_TSIG_SIGNATURE_FAILURE,Response_Code = "BADKEY",XDM_CONST.DNS_RESPONSE_CODE_KEY_NOT_RECOGNIZED,Response_Code = "BADTIME",XDM_CONST.DNS_RESPONSE_CODE_SIGNATURE_OUT_OF_TIME_WINDOW,Response_Code = "BADMODE",XDM_CONST.DNS_RESPONSE_CODE_BAD_TKEY_MODE,Response_Code = "BADNAME",XDM_CONST.DNS_RESPONSE_CODE_DUPLICATE_KEY_NAME, Response_Code = "BADALG",XDM_CONST.DNS_RESPONSE_CODE_ALGORITHM_NOT_SUPPORTED,Response_Code = "BADTRUNC",XDM_CONST.DNS_RESPONSE_CODE_BAD_TRUNCATION, to_string(Response_Code)),	
xdm.network.dns.dns_question.name = domain,	
xdm.event.description = catagories;
///xdm.network.dns.opcode = query_type;	waiting for parsing rule 



[MODEL: dataset=jamf_pro_raw]// Fix for Jamf DM
alter
    outcome_result = coalesce(json_extract_scalar(Event, "$.successful"), json_extract_scalar(Event, "$.operationSuccessful"))
| alter
    xdm.target.resource.name = coalesce(json_extract_scalar(Event, "$.deviceName"), json_extract_scalar(Event, "$.computer.deviceName"), json_extract_scalar(Event, "$.name"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.deviceName")), ","), json_extract_scalar(Event, "$.targetDevice.deviceName"),arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.deviceName")), ","))
| alter
    xdm.source.ipv4 = coalesce(json_extract_scalar(Event, "$.ipAddress"), json_extract_scalar(Event, "$.computer.ipAddress"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.ipAddress")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.ipAddress")), ","))
| alter
    xdm.target.resource.id = coalesce(json_extract_scalar(Event, "$.jssID"), json_extract_scalar(Event, "$.computer.jssID"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.jssID")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.jssID")), ","))
| alter
    xdm.target.resource.type = coalesce(json_extract_scalar(Event, "$.model"), json_extract_scalar(Event, "$.computer.model"), json_extract_scalar(Event, "$.targetDevice.model"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.model")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.model")), ","))
| alter
    xdm.target.resource.sub_type = coalesce(json_extract_scalar(Event, "$.osVersion"), json_extract_scalar(Event, "$.computer.osVersion"), json_extract_scalar(Event, "$.targetDevice.osVersion"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.osVersion")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.osVersion")), ","))
| alter
    xdm.source.user.username = coalesce(json_extract_scalar(Event, "$.username"), json_extract_scalar(Event, "$.patchPolicyName"), json_extract_scalar(Event, "$.authorizedUsername"), json_extract_scalar(Event, "$.targetUser.username"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.username")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.username")), ","))
| alter
    xdm.event.id = json_extract_scalar(webhook, "$.id"),
    xdm.event.description = json_extract_scalar(webhook, "$.name"),
    xdm.event.type = json_extract_scalar(webhook, "$.webhookEvent"),
    xdm.event.outcome_reason = json_extract_scalar(Event, "$.trigger"),
    xdm.source.user.identifier = json_extract_scalar(Event, "$.patchPolicyId"),
    xdm.event.outcome = if(outcome_result = "false", XDM_CONST.OUTCOME_FAILED, outcome_result = "true", XDM_CONST.OUTCOME_SUCCESS, outcome_result = null, null, to_string(outcome_result)),
    xdm.event.operation_sub_type = json_extract_scalar(Event, "$.restAPIOperationType")
| alter
    xdm.target.host.mac_addresses = arraycreate(coalesce(json_extract_scalar(Event, "$.wifiMacAddress"), json_extract_scalar(Event, "$.macAddress"), json_extract_scalar(Event, "$.computer.macAddress"), json_extract_scalar(Event, "$.targetDevice.wifiMacAddress"), ""))
| alter
    xdm.target.host.device_id = coalesce(json_extract_scalar(Event, "$.serialNumber"), json_extract_scalar(Event, "$.computer.serialNumber"), json_extract_scalar(Event, "$.targetDevice.serialNumber"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.serialNumber")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.serialNumber")), ","))
| alter
    xdm.target.host.hardware_uuid = coalesce(json_extract_scalar(Event, "$.udid"), json_extract_scalar(Event, "$.computer.udid"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.udid")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.udid")), ","), json_extract_scalar(Event, "$.targetDevice.udid"));

/* -------------------------------------
   ---------- System mappings ----------
   ------------------------------------- */

/* --------------------------------- */

[MODEL: dataset=panw_ngfw_globalprotect_raw]
alter
    _empty_ip = "00000000000000000000ffff00000000"
| alter
    xdm.auth.auth_method = auth_method,
    xdm.event.description = event_id,
    xdm.event.duration = to_number(multiply(login_duration, 1000)),
    xdm.event.id = to_string(sequence_no),
    xdm.event.outcome = if(status="success", XDM_CONST.OUTCOME_SUCCESS, status="failure", XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN),
    xdm.event.outcome_reason = connection_error,
    xdm.event.tags = arraycreate("VPN"),
    xdm.event.operation = stage,
    xdm.event.original_event_type = "globalprotect",
    xdm.network.vpn.allocated_ipv4 = if(private_ip != _empty_ip, private_ip),
    xdm.network.vpn.allocated_ipv6 = if (private_ipv6 != _empty_ip, private_ipv6),
    xdm.observer.name = log_source_name,
    xdm.observer.type = log_source,
    xdm.observer.unique_identifier = log_source_id,
    xdm.source.application.version = to_string(endpoint_gp_version),
    xdm.source.host.device_id = host_id,
    xdm.source.host.hardware_uuid = host_id,
    xdm.source.host.mac_addresses = if(host_id contains ":", arraycreate(host_id)),
    xdm.source.host.hostname = endpoint_device_name,
    xdm.source.host.os = endpoint_os_version,
    xdm.source.host.os_family = if(endpoint_os_type="Windows", XDM_CONST.OS_FAMILY_WINDOWS , endpoint_os_type in ("macOS", "Mac"), XDM_CONST.OS_FAMILY_MACOS, endpoint_os_type="Linux", XDM_CONST.OS_FAMILY_LINUX, uppercase(endpoint_os_version)),
    xdm.source.ipv4 = if(public_ip != _empty_ip, public_ip),
    xdm.source.ipv6 = if(public_ipv6 != _empty_ip, public_ipv6),
    xdm.source.location.country = if(len(source_region)=2, source_region),
    xdm.source.identity.domain = source_user_info_domain,
    xdm.source.identity.username = source_user,
    xdm.target.application.name = "GlobalProtect",
    xdm.target.host.hostname = gateway;
/* --------------------------------- */

[MODEL: dataset=panw_ngfw_hipmatch_raw]
alter
    _os_family = arrayindex(split(endpoint_os_type), 0),
    _host_mac_address = if(host_id = null, source_device_mac, if(host_id contains ":", host_id))
| alter
    xdm.event.id = to_string(sequence_no),
    xdm.event.original_event_type = "hipmatch",
    xdm.target.application.name = sub_type,
    xdm.event.type = hip_match_name,
    xdm.observer.name = log_source_name,
    xdm.observer.type = log_source,
    xdm.observer.unique_identifier = log_source_id,
    xdm.source.application.version = config_version,
    xdm.source.host.device_id = coalesce(host_id, source_device_mac),
    xdm.source.host.hostname = endpoint_device_name,
    xdm.source.host.mac_addresses = if(_host_mac_address != null, arraycreate(_host_mac_address)),
    xdm.source.host.os = endpoint_os_type,
    xdm.source.host.os_family = if(_os_family="windows", XDM_CONST.OS_FAMILY_WINDOWS , _os_family in ("macos", "mac"), XDM_CONST.OS_FAMILY_MACOS, _os_family in ("ios", "iOS"), XDM_CONST.OS_FAMILY_IOS, _os_family="chromeos", XDM_CONST.OS_FAMILY_CHROMEOS, _os_family="linux", XDM_CONST.OS_FAMILY_LINUX, _os_family="android", XDM_CONST.OS_FAMILY_ANDROID, _os_family),
    xdm.source.host.hardware_uuid = endpoint_serial_number,
    xdm.source.ipv4 = source_ip,
    xdm.source.ipv6 = if(source_ip_v6 contains ":", source_ip_v6),
    xdm.source.identity.domain = source_user_info_domain,
    xdm.source.identity.username = source_user_info_name
    ;
/* --------------------------------- */

[RULE: ngfw_standalone]
alter
    _empty_ip = "00000000000000000000ffff00000000",
    _is_nat = to_boolean(is_nat),
    _is_proxy = to_boolean(is_proxy),
    _source_port = to_integer(source_port),
    _dest_port = to_integer(dest_port),
    _is_dest_ipv6 = if(dest_ip contains ":"),
    _is_source_ipv6 = if(source_ip contains ":"),
    _session_id = to_string(session_id)
| alter
    xdm.event.id = _session_id,
    xdm.event.operation_sub_type = sub_type,
    xdm.event.type = log_type,
    xdm.intermediate.ipv4 = if(_is_proxy = True and _is_dest_ipv6 = False and dest_ip != _empty_ip, dest_ip),
    xdm.intermediate.ipv6 = if(_is_proxy = True and _is_dest_ipv6 = True, dest_ip),
    xdm.intermediate.is_nat = _is_nat,
    xdm.intermediate.is_proxy = _is_proxy,
    xdm.intermediate.port = if(_is_proxy = True, _dest_port),
    xdm.network.application_protocol = app,
    xdm.network.application_protocol_category = app_category,
    xdm.network.application_protocol_subcategory = app_sub_category,
    xdm.network.ip_protocol = if(protocol="icmp", XDM_CONST.IP_PROTOCOL_ICMP, protocol="tcp", XDM_CONST.IP_PROTOCOL_TCP, protocol="udp", XDM_CONST.IP_PROTOCOL_UDP, protocol),
    xdm.network.rule = rule_matched,
    xdm.observer.action = action,
    xdm.observer.name = log_source_name,
    xdm.observer.type = log_source,
    xdm.observer.unique_identifier = log_source_id,
    xdm.session_context_id = _session_id,
    xdm.source.host.hostname = if(source_device_host not contains ":", source_device_host),
    xdm.source.host.device_category = source_device_category,
    xdm.source.host.device_id = source_device_mac,
    xdm.source.host.device_model = source_device_model,
    xdm.source.host.mac_addresses = if(source_device_mac != null, arraycreate(source_device_mac)),
    xdm.source.host.manufacturer = source_device_vendor,
    xdm.source.host.os = source_device_os,
    xdm.source.host.os_family = if(source_device_osfamily="Windows", XDM_CONST.OS_FAMILY_WINDOWS , source_device_osfamily in ("MacOS", "Mac"), XDM_CONST.OS_FAMILY_MACOS, source_device_osfamily in ("ios", "iOS"), XDM_CONST.OS_FAMILY_IOS, source_device_osfamily="Chromeos", XDM_CONST.OS_FAMILY_CHROMEOS, source_device_osfamily="Linux", XDM_CONST.OS_FAMILY_LINUX, source_device_osfamily="Android", XDM_CONST.OS_FAMILY_ANDROID, source_device_osfamily),
    xdm.source.interface = inbound_if,
    xdm.source.ipv4 = if(_is_source_ipv6 = False and source_ip != _empty_ip, source_ip),
    xdm.source.ipv6 = if(_is_source_ipv6 = True, source_ip),
    xdm.source.port = _source_port,
    xdm.source.identity.username = source_user,
    xdm.source.zone = from_zone,
    xdm.target.host.hostname = if(dest_device_host not contains ":", dest_device_host),
    xdm.target.host.device_category = dest_device_category,
    xdm.target.host.device_id = dest_device_mac,
    xdm.target.host.device_model = dest_device_model,
    xdm.target.host.mac_addresses = if(dest_device_mac != null, arraycreate(dest_device_mac)),
    xdm.target.host.manufacturer = dest_device_vendor,
    xdm.target.host.os = dest_device_os,
    xdm.target.host.os_family = if(dest_device_osfamily="Windows", XDM_CONST.OS_FAMILY_WINDOWS , dest_device_osfamily in ("MacOS", "Mac"), XDM_CONST.OS_FAMILY_MACOS, dest_device_osfamily in ("ios", "iOS"), XDM_CONST.OS_FAMILY_IOS, dest_device_osfamily="Chromeos", XDM_CONST.OS_FAMILY_CHROMEOS, dest_device_osfamily="Linux", XDM_CONST.OS_FAMILY_LINUX, dest_device_osfamily="Android", XDM_CONST.OS_FAMILY_ANDROID, dest_device_osfamily),
    xdm.target.interface = outbound_if,
    xdm.target.ipv4 = if(_is_dest_ipv6 = False and dest_ip != _empty_ip, dest_ip),
    xdm.target.ipv6 = if(_is_dest_ipv6 = True, dest_ip),
    xdm.target.port = _dest_port,
    xdm.target.identity.username = dest_user,
    xdm.target.zone = to_zone;
[RULE: url_threat_common_fields]
alter
    xdm.network.http.method = if(http_method = "get", XDM_CONST.HTTP_METHOD_GET, http_method = "post", XDM_CONST.HTTP_METHOD_POST, http_method = "connect", XDM_CONST.HTTP_METHOD_CONNECT, http_method = "head", XDM_CONST.HTTP_METHOD_HEAD, http_method = "put", XDM_CONST.HTTP_METHOD_PUT, http_method = "delete", XDM_CONST.HTTP_METHOD_DELETE, http_method = "options", XDM_CONST.HTTP_METHOD_OPTIONS, http_method);
[MODEL:dataset="panw_ngfw_traffic_raw"]
call ngfw_standalone
| alter
    _bytes_sent = to_integer(bytes_sent),
    _packets_sent = to_integer(packets_sent),
    _bytes_received = to_integer(bytes_received),
    _packets_received = to_integer(packets_received),
    _total_time_elapsed = to_integer(multiply(total_time_elapsed, 1000))
| alter
    xdm.source.sent_bytes = _bytes_sent,
    xdm.source.sent_packets = _packets_sent,
    xdm.target.sent_bytes = _bytes_received,
    xdm.target.sent_packets = _packets_received,
    xdm.event.original_event_type = "traffic",
    xdm.event.outcome = if(sub_type in ("drop", "deny"), XDM_CONST.OUTCOME_FAILED),
    xdm.event.duration = _total_time_elapsed;
[MODEL:dataset="panw_ngfw_filedata_raw"]
call ngfw_standalone
| alter
    xdm.alert.severity = vendor_severity,
    xdm.event.original_event_type = "file_data",
    xdm.network.http.url_category = url_category,
    xdm.observer.content_version = content_version,
    xdm.source.host.hardware_uuid = source_uuid,
    xdm.source.process.container_id = container_id,
    xdm.target.file.file_type = file_type,
    xdm.target.file.filename = file_name,
    xdm.target.file.extension = if(file_name contains ".", arrayindex(split(file_name, "."), -1)),
    xdm.target.file.path = file_url,
    xdm.target.file.sha256 = file_sha_256,
    xdm.target.host.hardware_uuid = dest_uuid;
[MODEL:dataset="panw_ngfw_threat_raw"]
call ngfw_standalone
| call url_threat_common_fields
| alter
        threat_category_lower = lowercase(threat_category)
| alter
    xdm.event.original_event_type = "threat",
    //xdm.network.http.url_category = url_category,
    xdm.network.http.url = if(file_sha_256 = null, file_name),
    xdm.source.host.fqdn = url_domain,
    xdm.target.file.filename = if(file_sha_256 != null, file_name),
    xdm.target.file.file_type = file_type,
    xdm.target.file.sha256 = file_sha_256,
    xdm.email.subject = subject_of_email,
    xdm.alert.original_threat_id = to_string(threat_id),
    xdm.alert.original_threat_name = threat_name,
    xdm.alert.category = if(threat_category_lower = "apk", XDM_CONST.THREAT_CATEGORY_APK, threat_category_lower = "dmg", XDM_CONST.THREAT_CATEGORY_DMG, threat_category_lower = "flash", XDM_CONST.THREAT_CATEGORY_FLASH, threat_category_lower = "java-class", XDM_CONST.THREAT_CATEGORY_JAVA_CLASS, threat_category_lower = "macho", XDM_CONST.THREAT_CATEGORY_MACHO, threat_category_lower = "office", XDM_CONST.THREAT_CATEGORY_OFFICE, threat_category_lower = "openoffice", XDM_CONST.THREAT_CATEGORY_OPENOFFICE, threat_category_lower = "pdf", XDM_CONST.THREAT_CATEGORY_PDF, threat_category_lower = "pe", XDM_CONST.THREAT_CATEGORY_PE, threat_category_lower = "pkg", XDM_CONST.THREAT_CATEGORY_PKG, threat_category_lower = "adware", XDM_CONST.THREAT_CATEGORY_ADWARE, threat_category_lower = "autogen", XDM_CONST.THREAT_CATEGORY_AUTOGEN, threat_category_lower = "backdoor", XDM_CONST.THREAT_CATEGORY_BACKDOOR, threat_category_lower = "botnet", XDM_CONST.THREAT_CATEGORY_BOTNET, threat_category_lower = "browser-hijack", XDM_CONST.THREAT_CATEGORY_BROWSER_HIJACK, threat_category_lower = "cryptominer", XDM_CONST.THREAT_CATEGORY_CRYPTOMINER, threat_category_lower = "data-theft", XDM_CONST.THREAT_CATEGORY_DATA_THEFT, threat_category_lower = "dns", XDM_CONST.THREAT_CATEGORY_DNS, threat_category_lower = "dns-security", XDM_CONST.THREAT_CATEGORY_DNS_SECURITY, threat_category_lower = "dns-wildfire", XDM_CONST.THREAT_CATEGORY_DNS_WILDFIRE, threat_category_lower = "downloader", XDM_CONST.THREAT_CATEGORY_DOWNLOADER, threat_category_lower = "fraud", XDM_CONST.THREAT_CATEGORY_FRAUD, threat_category_lower = "hacktool", XDM_CONST.THREAT_CATEGORY_HACKTOOL, threat_category_lower = "keylogger", XDM_CONST.THREAT_CATEGORY_KEYLOGGER, threat_category_lower = "networm", XDM_CONST.THREAT_CATEGORY_NETWORM, threat_category_lower = "phishing-kit", XDM_CONST.THREAT_CATEGORY_PHISHING_KIT, threat_category_lower = "post-exploitation", XDM_CONST.THREAT_CATEGORY_POST_EXPLOITATION, threat_category_lower = "webshell", XDM_CONST.THREAT_CATEGORY_WEBSHELL, threat_category_lower = "spyware", XDM_CONST.THREAT_CATEGORY_SPYWARE, threat_category_lower = "brute force", XDM_CONST.THREAT_CATEGORY_BRUTE_FORCE, threat_category_lower = "code execution", XDM_CONST.THREAT_CATEGORY_CODE_EXECUTION, threat_category_lower = "code-obfuscation", XDM_CONST.THREAT_CATEGORY_CODE_OBFUSCATION, threat_category_lower = "dos", XDM_CONST.THREAT_CATEGORY_DOS, threat_category_lower = "exploit-kit", XDM_CONST.THREAT_CATEGORY_EXPLOIT_KIT, threat_category_lower = "info-leak", XDM_CONST.THREAT_CATEGORY_INFO_LEAK, threat_category_lower = "insecure-credentials", XDM_CONST.THREAT_CATEGORY_INSECURE_CREDENTIALS, threat_category_lower = "overflow", XDM_CONST.THREAT_CATEGORY_OVERFLOW, threat_category_lower = "phishing", XDM_CONST.THREAT_CATEGORY_PHISHING, threat_category_lower = "protocol-anomaly", XDM_CONST.THREAT_CATEGORY_PROTOCOL_ANOMALY, threat_category_lower = "sql-injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION, to_string(threat_category)),
    xdm.alert.severity = severity,
    xdm.alert.description = verdict;
[MODEL:dataset="panw_ngfw_url_raw"]
call ngfw_standalone
| call url_threat_common_fields
| alter
    xdm.event.original_event_type = "url",
    xdm.network.http.url = uri,
    xdm.network.http.url_category = url_category,
    xdm.network.http.content_type = content_type,
    xdm.source.user_agent = user_agent,
    xdm.network.http.referrer = referer,
    xdm.network.http.domain = url_domain,
    xdm.event.outcome = if(action = "allow", XDM_CONST.OUTCOME_SUCCESS,
						action = "alert", XDM_CONST.OUTCOME_SUCCESS,
						action = "block-url", XDM_CONST.OUTCOME_FAILED,
						action = "block-continue", XDM_CONST.OUTCOME_PARTIAL,
						action = "continue", XDM_CONST.OUTCOME_SUCCESS,
						action = "block-override", XDM_CONST.OUTCOME_PARTIAL,
						action = "override-lockout", XDM_CONST.OUTCOME_PARTIAL,
						action = "override", XDM_CONST.OUTCOME_SUCCESS),
    xdm.event.outcome_reason = action;
/* --------------------------------- */

[MODEL: dataset=xdr_data]
// Story mappings
filter
    event_type in (ENUM.STORY, ENUM.VPN_EVENT)
| alter
    is_auth_story = if(event_type=ENUM.STORY and dfe_labels contains "authentication"),
    is_network_story = if(event_type=ENUM.STORY),
    is_vpn_story = if(event_type=ENUM.VPN_EVENT),
    dns_resolutions = arrayindex(dns_resolutions, 0)
| alter
    action_rpc_items = arrayindex(action_rpc_items, 0),
    agent_interface_map = to_json_string(agent_interface_map)->[],
    backtrace_identities = arrayindex(backtrace_identities, 0),
    dst_action_external_hostname_as_ip = if(ip_to_int(dst_action_external_hostname) != null, dst_action_external_hostname),
    dst_agent_interface_map = to_json_string(dst_agent_interface_map)->[],
    file_data = arrayindex(file_data, 0),
    is_kerberos_story = if(krb_tgt_data != null or krb_tgs_data != null),
    is_ntlm_story = if(ntlm_auth_data != null),
    krb_error_code = coalesce(krb_tgs_data->error_code, krb_tgt_data->error_code),
    krb_req_kdc_options = coalesce(krb_tgs_data->req_kdc_options, krb_tgt_data->req_kdc_options),
    krb_req_msg_type =coalesce(krb_tgs_data->req_msg_type, krb_tgt_data->req_msg_type),
    krb_rsp_ticket_enc_type = coalesce(krb_tgs_data->rsp_ticket_enc_type, krb_tgt_data->rsp_ticket_enc_type, to_integer(action_evtlog_data_fields->TicketEncryptionType)),
    krb_spn_type = coalesce(krb_tgs_data->spn_type, krb_tgt_data->spn_type),
    krb_tgt_preauth_type = krb_tgt_data->preauth_type,
    krb_user_type = coalesce(krb_tgs_data->user_type, krb_tgt_data->user_type),
    ldap_operation = ldap_data->operation,
    ldap_scope = ldap_data->scope,
    resource_record_type = dns_resolutions->type,
    ssl_data = arrayindex(ssl_data, 0)
| alter
    _insert_time = to_timestamp(story_publish_timestamp, "MILLIS"),
    xdm.alert.original_alert_id = if(is_network_story=True, arrayindex(action_threat_ids, 0)),
    xdm.alert.severity = if(is_network_story=True, file_data->severity),
    xdm.auth.auth_method = if(is_vpn_story=True or is_auth_story= True, auth_method),
    xdm.auth.is_mfa_needed = if(is_auth_story=True, auth_mfa_needed),
    xdm.auth.kerberos_tgt.cname_type = if(is_auth_story=True, if(krb_user_type=0, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_UNKNOWN, krb_user_type=1, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_PRINCIPAL, krb_user_type=2, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_INST, krb_user_type=3, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_HST, krb_user_type=4, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_XHST, krb_user_type=5, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_UID, krb_user_type=6, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_X500_PRINCIPAL, krb_user_type=7, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SMTP_NAME, krb_user_type=10, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_ENTERPRISE, to_string(krb_user_type))),
    xdm.auth.kerberos_tgt.cname_values = if(is_auth_story=True, coalesce(krb_tgs_data->cname_values[], krb_tgt_data->cname_values[])),
    xdm.auth.kerberos_tgt.encryption_type = if(krb_rsp_ticket_enc_type=1, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_CRC, krb_rsp_ticket_enc_type=2, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD4, krb_rsp_ticket_enc_type=3, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD5, krb_rsp_ticket_enc_type=4, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_RAW, krb_rsp_ticket_enc_type=5, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_MD5, krb_rsp_ticket_enc_type=6, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_RAW, krb_rsp_ticket_enc_type=7, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1, krb_rsp_ticket_enc_type=8, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_HMAC_SHA1, krb_rsp_ticket_enc_type=9, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DSAWITHSHA1_CMSOID, krb_rsp_ticket_enc_type=10, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_MD5WITHRSAENCRYPTION_CMSOID, krb_rsp_ticket_enc_type=11, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SHA1WITHRSAENCRYPTION_CMSOID, krb_rsp_ticket_enc_type=12, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC2CBC_ENVOID, krb_rsp_ticket_enc_type=13, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAENCRYPTION_ENVOID, krb_rsp_ticket_enc_type=14, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAES_OAEP_ENV_OID, krb_rsp_ticket_enc_type=15, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_EDE3_CBC_ENV_OID, krb_rsp_ticket_enc_type=16, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1_KD, krb_rsp_ticket_enc_type=17, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, krb_rsp_ticket_enc_type=18, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96, krb_rsp_ticket_enc_type=19, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA256_128, krb_rsp_ticket_enc_type=20, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA384_192, krb_rsp_ticket_enc_type=23, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC, krb_rsp_ticket_enc_type=24, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC_EXP, krb_rsp_ticket_enc_type=25, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA128_CTS_CMAC, krb_rsp_ticket_enc_type=26, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA256_CTS_CMAC, krb_rsp_ticket_enc_type=65, XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SUBKEY_KEYMATERIAL, to_string(krb_rsp_ticket_enc_type)),
    xdm.auth.kerberos_tgt.error_code = if(krb_error_code=0, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_NONE, krb_error_code=1, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_NAME_EXP, krb_error_code=2, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SERVICE_EXP, krb_error_code=3, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_BAD_PVNO, krb_error_code=4, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_C_OLD_MAST_KVNO, krb_error_code=5, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_S_OLD_MAST_KVNO, krb_error_code=6, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_C_PRINCIPAL_UNKNOWN, krb_error_code=7, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_S_PRINCIPAL_UNKNOWN, krb_error_code=8, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PRINCIPAL_NOT_UNIQUE, krb_error_code=9, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_NULL_KEY, krb_error_code=10, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CANNOT_POSTDATE, krb_error_code=11, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_NEVER_VALID, krb_error_code=12, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_POLICY, krb_error_code=13, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_BADOPTION, krb_error_code=14, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_ETYPE_NOSUPP, krb_error_code=15, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SUMTYPE_NOSUPP, krb_error_code=16, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PADATA_TYPE_NOSUPP, krb_error_code=17, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_TRTYPE_NOSUPP, krb_error_code=18, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CLIENT_REVOKED, krb_error_code=19, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SERVICE_REVOKED, krb_error_code=20, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_TGT_REVOKED, krb_error_code=21, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CLIENT_NOTYET, krb_error_code=22, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SERVICE_NOTYET, krb_error_code=23, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_KEY_EXPIRED, krb_error_code=24, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PREAUTH_FAILED, krb_error_code=25, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PREAUTH_REQUIRED, krb_error_code=26, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SERVER_NOMATCH, krb_error_code=27, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_MUST_USE_USER2USER, krb_error_code=28, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PATH_NOT_ACCEPTED, krb_error_code=29, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_SVC_UNAVAILABLE, krb_error_code=31, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BAD_INTEGRITY, krb_error_code=32, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_TKT_EXPIRED, krb_error_code=33, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_TKT_NYV, krb_error_code=34, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_REPEAT, krb_error_code=35, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_NOT_US, krb_error_code=36, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADMATCH, krb_error_code=37, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_SKEW, krb_error_code=38, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADADDR, krb_error_code=39, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADVERSION, krb_error_code=40, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_MSG_TYPE, krb_error_code=41, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_MODIFIED, krb_error_code=42, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADORDER, krb_error_code=44, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADKEYVER, krb_error_code=45, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_NOKEY, krb_error_code=46, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_MUT_FAIL, krb_error_code=47, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADDIRECTION, krb_error_code=48, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_METHOD, krb_error_code=49, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_BADSEQ, krb_error_code=50, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_INAPP_CKSUM, krb_error_code=51, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_PATH_NOT_ACCEPTED, krb_error_code=52, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_RESPONSE_TOO_BIG, krb_error_code=60, XDM_CONST.KERBEROS_ERROR_CODE_ERR_GENERIC, krb_error_code=61, XDM_CONST.KERBEROS_ERROR_CODE_ERR_FIELD_TOOLONG, krb_error_code=62, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC__CLIENT_NOT_TRUSTED, krb_error_code=63, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC__KDC_NOT_TRUSTED, krb_error_code=64, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC__INVALID_SIG, krb_error_code=65, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_KEY_TOO_WEAK, krb_error_code=66, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CERTIFICATE_MISMATCH, krb_error_code=67, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_NO_TGT, krb_error_code=68, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_WRONG_REALM, krb_error_code=69, XDM_CONST.KERBEROS_ERROR_CODE_ERR_AP_USER_TO_USER_REQUIRED, krb_error_code=70, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CANT_VERIFY_CERTIFICATE, krb_error_code=71, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_INVALID_CERTIFICATE, krb_error_code=72, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_REVOKED_CERTIFICATE, krb_error_code=73, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_REVOCATION_STATUS_UNKNOWN, krb_error_code=74, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_REVOCATION_STATUS_UNAVAILABLE, krb_error_code=75, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CLIENT_NAME_MISMATCH, krb_error_code=76, XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_KDC_NAME_MISMATCH, to_string(krb_error_code)),
    xdm.auth.kerberos_tgt.kdc_options = if(is_auth_story=True, if(krb_req_kdc_options=0, XDM_CONST.KERBEROS_KDC_OPTION_RESERVED, krb_req_kdc_options=1, XDM_CONST.KERBEROS_KDC_OPTION_FORWARDABLE, krb_req_kdc_options=2, XDM_CONST.KERBEROS_KDC_OPTION_FORWARDED, krb_req_kdc_options=3, XDM_CONST.KERBEROS_KDC_OPTION_PROXIABLE, krb_req_kdc_options=4, XDM_CONST.KERBEROS_KDC_OPTION_PROXY, krb_req_kdc_options=5, XDM_CONST.KERBEROS_KDC_OPTION_ALLOW_POST_DATE, krb_req_kdc_options=6, XDM_CONST.KERBEROS_KDC_OPTION_POST_DATED, krb_req_kdc_options=7, XDM_CONST.KERBEROS_KDC_OPTION_INVALID, krb_req_kdc_options=8, XDM_CONST.KERBEROS_KDC_OPTION_RENEWABLE, krb_req_kdc_options=9, XDM_CONST.KERBEROS_KDC_OPTION_INITIAL, krb_req_kdc_options=10, XDM_CONST.KERBEROS_KDC_OPTION_PRE_AUTHENT, krb_req_kdc_options=11, XDM_CONST.KERBEROS_KDC_OPTION_HW_AUTHENT, krb_req_kdc_options=12, XDM_CONST.KERBEROS_KDC_OPTION_REQUEST_ANONYMOUS, krb_req_kdc_options=13, XDM_CONST.KERBEROS_KDC_OPTION_OK_AS_DELEGATE, krb_req_kdc_options=15, XDM_CONST.KERBEROS_KDC_OPTION_CANONICALIZE, krb_req_kdc_options=26, XDM_CONST.KERBEROS_KDC_OPTION_DISABLE_TRANSITED_CHECK, krb_req_kdc_options=27, XDM_CONST.KERBEROS_KDC_OPTION_RENEWABLE_OK, krb_req_kdc_options=28, XDM_CONST.KERBEROS_KDC_OPTION_ENC_TKT_IN_SKEY, krb_req_kdc_options=30, XDM_CONST.KERBEROS_KDC_OPTION_RENEW, krb_req_kdc_options=31, XDM_CONST.KERBEROS_KDC_OPTION_VALIDATE, to_string(krb_req_kdc_options))),
    xdm.auth.kerberos_tgt.msg_type = if(is_auth_story=True, if(krb_req_msg_type=10, XDM_CONST.KERBEROS_MSG_TYPE_AS_REQ, krb_req_msg_type=11, XDM_CONST.KERBEROS_MSG_TYPE_AS_REP, krb_req_msg_type=12, XDM_CONST.KERBEROS_MSG_TYPE_TGS_REQ, krb_req_msg_type=13, XDM_CONST.KERBEROS_MSG_TYPE_TGS_REP, krb_req_msg_type=14, XDM_CONST.KERBEROS_MSG_TYPE_AP_REQ, krb_req_msg_type=15, XDM_CONST.KERBEROS_MSG_TYPE_AP_REP, krb_req_msg_type=16, XDM_CONST.KERBEROS_MSG_TYPE_RESERVED16, krb_req_msg_type=17, XDM_CONST.KERBEROS_MSG_TYPE_RESERVED17, krb_req_msg_type=20, XDM_CONST.KERBEROS_MSG_TYPE_SAFE, krb_req_msg_type=21, XDM_CONST.KERBEROS_MSG_TYPE_PRIV, krb_req_msg_type=22, XDM_CONST.KERBEROS_MSG_TYPE_CRED, krb_req_msg_type=30, XDM_CONST.KERBEROS_MSG_TYPE_ERROR, to_string(krb_req_msg_type))),
    xdm.auth.kerberos_tgt.padata_prefix = if(is_auth_story=True, coalesce(krb_tgs_data->req_padata_prefix, krb_tgt_data->req_padata_prefix)),
    xdm.auth.kerberos_tgt.padata_type = if(is_auth_story=True, if(krb_tgt_preauth_type != null, if(krb_tgt_preauth_type=1, XDM_CONST.KERBEROS_PA_TYPE_TGS_REQ, krb_tgt_preauth_type=2, XDM_CONST.KERBEROS_PA_TYPE_ENC_TIMESTAMP, krb_tgt_preauth_type=3, XDM_CONST.KERBEROS_PA_TYPE_PW_SALT, krb_tgt_preauth_type=5, XDM_CONST.KERBEROS_PA_TYPE_ENC_UNIX_TIME, krb_tgt_preauth_type=6, XDM_CONST.KERBEROS_PA_TYPE_SANDIA_SECUREID, krb_tgt_preauth_type=7, XDM_CONST.KERBEROS_PA_TYPE_SESAME, krb_tgt_preauth_type=8, XDM_CONST.KERBEROS_PA_TYPE_OSF_DCE, krb_tgt_preauth_type=9, XDM_CONST.KERBEROS_PA_TYPE_CYBERSAFE_SECUREID, krb_tgt_preauth_type=10, XDM_CONST.KERBEROS_PA_TYPE_AFS3_SALT, krb_tgt_preauth_type=11, XDM_CONST.KERBEROS_PA_TYPE_ETYPE_INFO, krb_tgt_preauth_type=12, XDM_CONST.KERBEROS_PA_TYPE_SAM_CHALLENGE, krb_tgt_preauth_type=13, XDM_CONST.KERBEROS_PA_TYPE_SAM_RESPONSE, krb_tgt_preauth_type=14, XDM_CONST.KERBEROS_PA_TYPE_PK_AS_REQ_OLD, krb_tgt_preauth_type=15, XDM_CONST.KERBEROS_PA_TYPE_PK_AS_REP_OLD, krb_tgt_preauth_type=16, XDM_CONST.KERBEROS_PA_TYPE_PK_AS_REQ, krb_tgt_preauth_type=17, XDM_CONST.KERBEROS_PA_TYPE_PK_AS_REP, krb_tgt_preauth_type=18, XDM_CONST.KERBEROS_PA_TYPE_PK_OCSP_RESPONSE, krb_tgt_preauth_type=19, XDM_CONST.KERBEROS_PA_TYPE_ETYPE_INFO2, krb_tgt_preauth_type=20, XDM_CONST.KERBEROS_PA_TYPE_USE_SPECIFIED_KVNO, krb_tgt_preauth_type=21, XDM_CONST.KERBEROS_PA_TYPE_SAM_REDIRECT, krb_tgt_preauth_type=22, XDM_CONST.KERBEROS_PA_TYPE_GET_FROM_TYPED_DATA, krb_tgt_preauth_type=23, XDM_CONST.KERBEROS_PA_TYPE_SAM_ETYPE_INFO, krb_tgt_preauth_type=24, XDM_CONST.KERBEROS_PA_TYPE_ALT_PRINC, krb_tgt_preauth_type=25, XDM_CONST.KERBEROS_PA_TYPE_SERVER_REFERRAL, krb_tgt_preauth_type=30, XDM_CONST.KERBEROS_PA_TYPE_SAM_CHALLENGE2, krb_tgt_preauth_type=31, XDM_CONST.KERBEROS_PA_TYPE_SAM_RESPONSE2, krb_tgt_preauth_type=41, XDM_CONST.KERBEROS_PA_TYPE_EXTRA_TGT, krb_tgt_preauth_type=101, XDM_CONST.KERBEROS_PA_TYPE_TD_PKINIT_CMS_CERTIFICATES, krb_tgt_preauth_type=102, XDM_CONST.KERBEROS_PA_TYPE_TD_KRB_PRINCIPAL, krb_tgt_preauth_type=103, XDM_CONST.KERBEROS_PA_TYPE_TD_KRB_REALM, krb_tgt_preauth_type=104, XDM_CONST.KERBEROS_PA_TYPE_TD_TRUSTED_CERTIFIERS, krb_tgt_preauth_type=105, XDM_CONST.KERBEROS_PA_TYPE_TD_CERTIFICATE_INDEX, krb_tgt_preauth_type=106, XDM_CONST.KERBEROS_PA_TYPE_TD_APP_DEFINED_ERROR, krb_tgt_preauth_type=107, XDM_CONST.KERBEROS_PA_TYPE_TD_REQ_NONCE, krb_tgt_preauth_type=108, XDM_CONST.KERBEROS_PA_TYPE_TD_REQ_SEQ, krb_tgt_preauth_type=109, XDM_CONST.KERBEROS_PA_TYPE_TD_DH_PARAMETERS, krb_tgt_preauth_type=111, XDM_CONST.KERBEROS_PA_TYPE_TD_CMS_DIGEST_ALGORITHMS, krb_tgt_preauth_type=112, XDM_CONST.KERBEROS_PA_TYPE_TD_CERT_DIGEST_ALGORITHMS, krb_tgt_preauth_type=128, XDM_CONST.KERBEROS_PA_TYPE_PAC_REQUEST, krb_tgt_preauth_type=129, XDM_CONST.KERBEROS_PA_TYPE_FOR_USER, krb_tgt_preauth_type=130, XDM_CONST.KERBEROS_PA_TYPE_FOR_X509_USER, krb_tgt_preauth_type=131, XDM_CONST.KERBEROS_PA_TYPE_FOR_CHECK_DUPS, krb_tgt_preauth_type=132, XDM_CONST.KERBEROS_PA_TYPE_AS_CHECKSUM, krb_tgt_preauth_type=133, XDM_CONST.KERBEROS_PA_TYPE_FX_COOKIE, krb_tgt_preauth_type=134, XDM_CONST.KERBEROS_PA_TYPE_AUTHENTICATION_SET, krb_tgt_preauth_type=135, XDM_CONST.KERBEROS_PA_TYPE_AUTH_SET_SELECTED, krb_tgt_preauth_type=136, XDM_CONST.KERBEROS_PA_TYPE_FX_FAST, krb_tgt_preauth_type=137, XDM_CONST.KERBEROS_PA_TYPE_FX_ERROR, krb_tgt_preauth_type=138, XDM_CONST.KERBEROS_PA_TYPE_ENCRYPTED_CHALLENGE, krb_tgt_preauth_type=141, XDM_CONST.KERBEROS_PA_TYPE_OTP_CHALLENGE, krb_tgt_preauth_type=142, XDM_CONST.KERBEROS_PA_TYPE_OTP_REQUEST, krb_tgt_preauth_type=143, XDM_CONST.KERBEROS_PA_TYPE_OTP_CONFIRM, krb_tgt_preauth_type=144, XDM_CONST.KERBEROS_PA_TYPE_OTP_PIN_CHANGE, krb_tgt_preauth_type=145, XDM_CONST.KERBEROS_PA_TYPE_EPAK_AS_REQ, krb_tgt_preauth_type=146, XDM_CONST.KERBEROS_PA_TYPE_EPAK_AS_REP, krb_tgt_preauth_type=147, XDM_CONST.KERBEROS_PA_TYPE_PKINIT_KX, krb_tgt_preauth_type=148, XDM_CONST.KERBEROS_PA_TYPE_PKU2U_NAME, krb_tgt_preauth_type=149, XDM_CONST.KERBEROS_PA_TYPE_REQ_ENC_PA_REP, krb_tgt_preauth_type=150, XDM_CONST.KERBEROS_PA_TYPE_AS_FRESHNESS, krb_tgt_preauth_type=165, XDM_CONST.KERBEROS_PA_TYPE_SUPPORTED_ETYPES, krb_tgt_preauth_type=166, XDM_CONST.KERBEROS_PA_TYPE_EXTENDED_ERROR, to_string(krb_tgt_preauth_type)))),
    xdm.auth.kerberos_tgt.renew_ticket_expiration = if(is_auth_story=True, coalesce(krb_tgs_data->renew_ticket_expiration_time, krb_tgt_data->renew_ticket_expiration_time)),
    xdm.auth.kerberos_tgt.spn_type = if(is_auth_story=True, if(krb_spn_type=0, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_UNKNOWN, krb_spn_type=1, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_PRINCIPAL, krb_spn_type=2, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_INST, krb_spn_type=3, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_HST, krb_spn_type=4, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SRV_XHST, krb_spn_type=5, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_UID, krb_spn_type=6, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_X500_PRINCIPAL, krb_spn_type=7, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_SMTP_NAME, krb_spn_type=10, XDM_CONST.KERBEROS_PRINCIPAL_TYPE_ENTERPRISE, to_string(krb_spn_type))),
    xdm.auth.kerberos_tgt.spn_values = if(is_auth_story=True, coalesce(krb_tgs_data->sname_values[], krb_tgt_data->sname_values[])),
    xdm.auth.kerberos_tgt.ticket_expiration = if(is_auth_story=True, coalesce(krb_tgs_data->ticket_expiration_time, krb_tgt_data->ticket_expiration_time)),
    xdm.auth.kerberos_tgt.ticket_prefix = if(is_auth_story=True, coalesce(krb_tgs_data->rsp_ticket_prefix, krb_tgt_data->rsp_ticket_prefix)),
    xdm.auth.ntlm.challenge = if(is_auth_story=True, ntlm_auth_data->client_challenge),
    xdm.auth.ntlm.dns_domain = if(is_auth_story=True, ntlm_auth_data->dst_dns_domain_name),
    xdm.auth.ntlm.dns_hostname = if(is_auth_story=True, ntlm_auth_data->dst_dns_host_name),
    xdm.auth.ntlm.dns_three = if(is_auth_story=True, ntlm_auth_data->dst_dns_tree_name),
    xdm.auth.ntlm.domain = if(is_auth_story=True, ntlm_auth_data->domain_name),
    xdm.auth.ntlm.hostname = if(is_auth_story=True, ntlm_auth_data->host_name),
    xdm.auth.ntlm.ntproof = if(is_auth_story=True, ntlm_auth_data->ntproofstr),
    xdm.auth.ntlm.target = if(is_auth_story=True, arrayindex(ntlm_auth_data->dst_target_name, 0)),
    xdm.auth.ntlm.user_name = if(is_auth_story=True, ntlm_auth_data->user_name),
    xdm.auth.ntlm.version = if(is_auth_story=True, to_json_string(ntlm_auth_data)->major_version + "." + to_json_string(ntlm_auth_data)->minor_version),
    xdm.event.description = if(is_vpn_story=True, vpn_event_description),
    xdm.event.duration = if(is_network_story=True, action_session_duration),
    xdm.event.id = if(is_auth_story=True or is_vpn_story=True, backtrace_identities->event_id, story_id_original),
    xdm.event.is_completed = if(is_network_story=True, action_network_stats_is_last),
    xdm.event.operation_sub_type = backtrace_identities->event_sub_type,
    xdm.event.outcome = if(is_auth_story=True or is_vpn_story=True, if(auth_outcome="SUCCESS", XDM_CONST.OUTCOME_SUCCESS, auth_outcome="FAILURE", XDM_CONST.OUTCOME_FAILED, auth_outcome), if(action_network_success=True, XDM_CONST.OUTCOME_SUCCESS, action_network_success=False, XDM_CONST.OUTCOME_FAILED)),
    xdm.event.outcome_reason = auth_outcome_reason,
    xdm.event.type = to_string(event_type),
    xdm.intermediate.host.device_id = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, if(dst_association_strength > 10, dst_agent_id))),
    xdm.intermediate.host.fqdn = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, dst_action_external_hostname)),
    xdm.intermediate.host.hostname = if(is_auth_story=True, auth_server, if(is_vpn_story=True, vpn_server)),
    xdm.intermediate.host.ipv4_addresses = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, split(dst_agent_ip_addresses, ","))),
    xdm.intermediate.host.ipv6_addresses = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, split(dst_agent_ip_addresses_v6, ","))),
    xdm.intermediate.host.mac_addresses = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, arraymap(dst_agent_interface_map, "@element"->mac))),
    xdm.intermediate.host.os = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, dst_agent_os_sub_type)),
    xdm.intermediate.host.os_family = if(is_auth_story=True, if(is_kerberos_story=True or is_ntlm_story=True, if(dst_agent_os_type=ENUM.AGENT_OS_WINDOWS, XDM_CONST.OS_FAMILY_WINDOWS, dst_agent_os_type=ENUM.AGENT_OS_MAC, XDM_CONST.OS_FAMILY_MACOS,  dst_agent_os_type=ENUM.AGENT_OS_LINUX, XDM_CONST.OS_FAMILY_LINUX, to_string(dst_agent_os_type)))),
    xdm.intermediate.ipv4 = if(action_network_is_ipv6=False and action_proxy=True, action_remote_ip),
    xdm.intermediate.ipv6 = if(action_network_is_ipv6=True and action_proxy=True, action_remote_ip),
    xdm.intermediate.is_internal_ip = if(action_proxy=True, dst_is_internal_ip),
    xdm.intermediate.is_nat = if(is_network_story=True, action_nat),
    xdm.intermediate.is_proxy = action_proxy,
    xdm.intermediate.port = if(action_proxy=True, action_remote_port),
    xdm.network.application_protocol = if(is_network_story=True, arrayindex(action_app_id_transitions, -1)),
    xdm.network.application_protocol_category = if(is_network_story=True, action_category_of_app_id),
    xdm.network.application_protocol_subcategory = action_sub_category_of_app_id,
    xdm.network.dcerpc.interface_uuid = if(is_network_story=True, action_rpc_items->interface_uuid),
    xdm.network.dcerpc.opnum = if(is_network_story=True, to_integer(action_rpc_items->opnum)),
    xdm.network.dcerpc.svcctl_buffer = if(is_network_story=True, action_rpc_items->req_svcctl_buffer),
    xdm.network.dns.dns_question.name = if(is_network_story=True, dns_query_name),
    xdm.network.dns.dns_question.type = if(is_network_story=True, if(dns_query_type="A", XDM_CONST.DNS_RECORD_TYPE_A,dns_query_type="AAAA", XDM_CONST.DNS_RECORD_TYPE_AAAA,dns_query_type="AFSDB", XDM_CONST.DNS_RECORD_TYPE_AFSDB,dns_query_type="APL", XDM_CONST.DNS_RECORD_TYPE_APL,dns_query_type="CAA", XDM_CONST.DNS_RECORD_TYPE_CAA,dns_query_type="CDNSKEY", XDM_CONST.DNS_RECORD_TYPE_CDNSKEY,dns_query_type="CDS", XDM_CONST.DNS_RECORD_TYPE_CDS,dns_query_type="CERT", XDM_CONST.DNS_RECORD_TYPE_CERT,dns_query_type="CNAME", XDM_CONST.DNS_RECORD_TYPE_CNAME,dns_query_type="CSYNC", XDM_CONST.DNS_RECORD_TYPE_CSYNC,dns_query_type="DHCID", XDM_CONST.DNS_RECORD_TYPE_DHCID,dns_query_type="DLV", XDM_CONST.DNS_RECORD_TYPE_DLV,dns_query_type="DNAME", XDM_CONST.DNS_RECORD_TYPE_DNAME,dns_query_type="DNSKEY", XDM_CONST.DNS_RECORD_TYPE_DNSKEY,dns_query_type="DS", XDM_CONST.DNS_RECORD_TYPE_DS,dns_query_type="EUI48", XDM_CONST.DNS_RECORD_TYPE_EUI48,dns_query_type="EUI64", XDM_CONST.DNS_RECORD_TYPE_EUI64,dns_query_type="HINFO", XDM_CONST.DNS_RECORD_TYPE_HINFO,dns_query_type="HIP", XDM_CONST.DNS_RECORD_TYPE_HIP,dns_query_type="HTTPS", XDM_CONST.DNS_RECORD_TYPE_HTTPS,dns_query_type="IPSECKEY", XDM_CONST.DNS_RECORD_TYPE_IPSECKEY,dns_query_type="KEY", XDM_CONST.DNS_RECORD_TYPE_KEY,dns_query_type="KX", XDM_CONST.DNS_RECORD_TYPE_KX,dns_query_type="LOC", XDM_CONST.DNS_RECORD_TYPE_LOC,dns_query_type="MX", XDM_CONST.DNS_RECORD_TYPE_MX,dns_query_type="NAPTR", XDM_CONST.DNS_RECORD_TYPE_NAPTR,dns_query_type="NS", XDM_CONST.DNS_RECORD_TYPE_NS,dns_query_type="NSEC", XDM_CONST.DNS_RECORD_TYPE_NSEC,dns_query_type="NSEC3", XDM_CONST.DNS_RECORD_TYPE_NSEC3,dns_query_type="NSEC3PARAM", XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM,dns_query_type="OPENPGPKEY", XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY,dns_query_type="PTR", XDM_CONST.DNS_RECORD_TYPE_PTR,dns_query_type="RRSIG", XDM_CONST.DNS_RECORD_TYPE_RRSIG,dns_query_type="RP", XDM_CONST.DNS_RECORD_TYPE_RP,dns_query_type="SIG", XDM_CONST.DNS_RECORD_TYPE_SIG,dns_query_type="SMIMEA", XDM_CONST.DNS_RECORD_TYPE_SMIMEA,dns_query_type="SOA", XDM_CONST.DNS_RECORD_TYPE_SOA,dns_query_type="SRV", XDM_CONST.DNS_RECORD_TYPE_SRV,dns_query_type="SSHFP", XDM_CONST.DNS_RECORD_TYPE_SSHFP,dns_query_type="SVCB", XDM_CONST.DNS_RECORD_TYPE_SVCB,dns_query_type="TA", XDM_CONST.DNS_RECORD_TYPE_TA,dns_query_type="TKEY", XDM_CONST.DNS_RECORD_TYPE_TKEY,dns_query_type="TLSA", XDM_CONST.DNS_RECORD_TYPE_TLSA,dns_query_type="TSIG", XDM_CONST.DNS_RECORD_TYPE_TSIG,dns_query_type="TXT", XDM_CONST.DNS_RECORD_TYPE_TXT,dns_query_type="URI", XDM_CONST.DNS_RECORD_TYPE_URI,dns_query_type="ZONEMD", XDM_CONST.DNS_RECORD_TYPE_ZONEMD, dns_query_type)),
    xdm.network.dns.dns_resource_record.name = if(is_network_story=True, dns_resolutions->name),
    xdm.network.dns.dns_resource_record.type = if(is_network_story=True, if(resource_record_type="A", XDM_CONST.DNS_RECORD_TYPE_A,resource_record_type="AAAA", XDM_CONST.DNS_RECORD_TYPE_AAAA,resource_record_type="AFSDB", XDM_CONST.DNS_RECORD_TYPE_AFSDB,resource_record_type="APL", XDM_CONST.DNS_RECORD_TYPE_APL,resource_record_type="CAA", XDM_CONST.DNS_RECORD_TYPE_CAA,resource_record_type="CDNSKEY", XDM_CONST.DNS_RECORD_TYPE_CDNSKEY,resource_record_type="CDS", XDM_CONST.DNS_RECORD_TYPE_CDS,resource_record_type="CERT", XDM_CONST.DNS_RECORD_TYPE_CERT,resource_record_type="CNAME", XDM_CONST.DNS_RECORD_TYPE_CNAME,resource_record_type="CSYNC", XDM_CONST.DNS_RECORD_TYPE_CSYNC,resource_record_type="DHCID", XDM_CONST.DNS_RECORD_TYPE_DHCID,resource_record_type="DLV", XDM_CONST.DNS_RECORD_TYPE_DLV,resource_record_type="DNAME", XDM_CONST.DNS_RECORD_TYPE_DNAME,resource_record_type="DNSKEY", XDM_CONST.DNS_RECORD_TYPE_DNSKEY,resource_record_type="DS", XDM_CONST.DNS_RECORD_TYPE_DS,resource_record_type="EUI48", XDM_CONST.DNS_RECORD_TYPE_EUI48,resource_record_type="EUI64", XDM_CONST.DNS_RECORD_TYPE_EUI64,resource_record_type="HINFO", XDM_CONST.DNS_RECORD_TYPE_HINFO,resource_record_type="HIP", XDM_CONST.DNS_RECORD_TYPE_HIP,resource_record_type="HTTPS", XDM_CONST.DNS_RECORD_TYPE_HTTPS,resource_record_type="IPSECKEY", XDM_CONST.DNS_RECORD_TYPE_IPSECKEY,resource_record_type="KEY", XDM_CONST.DNS_RECORD_TYPE_KEY,resource_record_type="KX", XDM_CONST.DNS_RECORD_TYPE_KX,resource_record_type="LOC", XDM_CONST.DNS_RECORD_TYPE_LOC,resource_record_type="MX", XDM_CONST.DNS_RECORD_TYPE_MX,resource_record_type="NAPTR", XDM_CONST.DNS_RECORD_TYPE_NAPTR,resource_record_type="NS", XDM_CONST.DNS_RECORD_TYPE_NS,resource_record_type="NSEC", XDM_CONST.DNS_RECORD_TYPE_NSEC,resource_record_type="NSEC3", XDM_CONST.DNS_RECORD_TYPE_NSEC3,resource_record_type="NSEC3PARAM", XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM,resource_record_type="OPENPGPKEY", XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY,resource_record_type="PTR", XDM_CONST.DNS_RECORD_TYPE_PTR,resource_record_type="RRSIG", XDM_CONST.DNS_RECORD_TYPE_RRSIG,resource_record_type="RP", XDM_CONST.DNS_RECORD_TYPE_RP,resource_record_type="SIG", XDM_CONST.DNS_RECORD_TYPE_SIG,resource_record_type="SMIMEA", XDM_CONST.DNS_RECORD_TYPE_SMIMEA,resource_record_type="SOA", XDM_CONST.DNS_RECORD_TYPE_SOA,resource_record_type="SRV", XDM_CONST.DNS_RECORD_TYPE_SRV,resource_record_type="SSHFP", XDM_CONST.DNS_RECORD_TYPE_SSHFP,resource_record_type="SVCB", XDM_CONST.DNS_RECORD_TYPE_SVCB,resource_record_type="TA", XDM_CONST.DNS_RECORD_TYPE_TA,resource_record_type="TKEY", XDM_CONST.DNS_RECORD_TYPE_TKEY,resource_record_type="TLSA", XDM_CONST.DNS_RECORD_TYPE_TLSA,resource_record_type="TSIG", XDM_CONST.DNS_RECORD_TYPE_TSIG,resource_record_type="TXT", XDM_CONST.DNS_RECORD_TYPE_TXT,resource_record_type="URI", XDM_CONST.DNS_RECORD_TYPE_URI,resource_record_type="ZONEMD", XDM_CONST.DNS_RECORD_TYPE_ZONEMD, resource_record_type)),
    xdm.network.dns.dns_resource_record.value = if(is_network_story=True, dns_resolutions->value),
    xdm.network.dns.is_response = if(is_network_story=True, if(dns_reply_code != null)),
    xdm.network.dns.response_code = if(is_network_story=True, if(dns_reply_code="No error", XDM_CONST.DNS_RESPONSE_CODE_NO_ERROR,dns_reply_code="Format Error", XDM_CONST.DNS_RESPONSE_CODE_FORMAT_ERROR,dns_reply_code="Server Failure", XDM_CONST.DNS_RESPONSE_CODE_SERVER_FAILURE,dns_reply_code="Non-Existent Domain", XDM_CONST.DNS_RESPONSE_CODE_NON_EXISTENT_DOMAIN,dns_reply_code="Not Implemented", XDM_CONST.DNS_RESPONSE_CODE_NOT_IMPLEMENTED,dns_reply_code="Query Refused", XDM_CONST.DNS_RESPONSE_CODE_QUERY_REFUSED,dns_reply_code="Name Exists when it should not", XDM_CONST.DNS_RESPONSE_CODE_NAME_EXISTS_WHEN_IT_SHOULD_NOT,dns_reply_code="RR Set Exists when it should not", XDM_CONST.DNS_RESPONSE_CODE_RR_SET_EXISTS_WHEN_IT_SHOULD_NOT,dns_reply_code="RR Set that should exist does not", XDM_CONST.DNS_RESPONSE_CODE_RR_SET_THAT_SHOULD_EXIST_DOES_NOT,dns_reply_code="Server Not Authoritative for zone", XDM_CONST.DNS_RESPONSE_CODE_SERVER_NOT_AUTHORITATIVE_FOR_ZONE,dns_reply_code="Name not contained in zone", XDM_CONST.DNS_RESPONSE_CODE_NAME_NOT_CONTAINED_IN_ZONE,dns_reply_code="Bad OPT Version", XDM_CONST.DNS_RESPONSE_CODE_BAD_OPT_VERSION,dns_reply_code="TSIG Signature Failure", XDM_CONST.DNS_RESPONSE_CODE_TSIG_SIGNATURE_FAILURE,dns_reply_code="Key not recognized", XDM_CONST.DNS_RESPONSE_CODE_KEY_NOT_RECOGNIZED,dns_reply_code="Signature out of time window", XDM_CONST.DNS_RESPONSE_CODE_SIGNATURE_OUT_OF_TIME_WINDOW,dns_reply_code="Bad TKEY Mode", XDM_CONST.DNS_RESPONSE_CODE_BAD_TKEY_MODE,dns_reply_code="Duplicate key name", XDM_CONST.DNS_RESPONSE_CODE_DUPLICATE_KEY_NAME,dns_reply_code="Algorithm not supported", XDM_CONST.DNS_RESPONSE_CODE_ALGORITHM_NOT_SUPPORTED,dns_reply_code="Bad Truncation", XDM_CONST.DNS_RESPONSE_CODE_BAD_TRUNCATION, dns_reply_code)),
    xdm.network.http.content_type = if(is_network_story=True, http_content_type),
    xdm.network.http.domain = if(is_network_story=True, http_server),
    xdm.network.http.method = if(is_network_story=True, if(http_method="ACL", XDM_CONST.HTTP_METHOD_ACL,http_method="BASELINE_CONTROL", XDM_CONST.HTTP_METHOD_BASELINE_CONTROL,http_method="BIND", XDM_CONST.HTTP_METHOD_BIND,http_method="CHECKIN", XDM_CONST.HTTP_METHOD_CHECKIN,http_method="CHECKOUT", XDM_CONST.HTTP_METHOD_CHECKOUT,http_method="CONNECT", XDM_CONST.HTTP_METHOD_CONNECT,http_method="COPY", XDM_CONST.HTTP_METHOD_COPY,http_method="DELETE", XDM_CONST.HTTP_METHOD_DELETE,http_method="GET", XDM_CONST.HTTP_METHOD_GET,http_method="HEAD", XDM_CONST.HTTP_METHOD_HEAD,http_method="LABEL", XDM_CONST.HTTP_METHOD_LABEL,http_method="LINK", XDM_CONST.HTTP_METHOD_LINK,http_method="LOCK", XDM_CONST.HTTP_METHOD_LOCK,http_method="MERGE", XDM_CONST.HTTP_METHOD_MERGE,http_method="MKACTIVITY", XDM_CONST.HTTP_METHOD_MKACTIVITY,http_method="MKCALENDAR", XDM_CONST.HTTP_METHOD_MKCALENDAR,http_method="MKCOL", XDM_CONST.HTTP_METHOD_MKCOL,http_method="MKREDIRECTREF", XDM_CONST.HTTP_METHOD_MKREDIRECTREF,http_method="MKWORKSPACE", XDM_CONST.HTTP_METHOD_MKWORKSPACE,http_method="MOVE", XDM_CONST.HTTP_METHOD_MOVE,http_method="OPTIONS", XDM_CONST.HTTP_METHOD_OPTIONS,http_method="ORDERPATCH", XDM_CONST.HTTP_METHOD_ORDERPATCH,http_method="PATCH", XDM_CONST.HTTP_METHOD_PATCH,http_method="POST", XDM_CONST.HTTP_METHOD_POST,http_method="PRI", XDM_CONST.HTTP_METHOD_PRI,http_method="PROPFIND", XDM_CONST.HTTP_METHOD_PROPFIND,http_method="PROPPATCH", XDM_CONST.HTTP_METHOD_PROPPATCH,http_method="PUT", XDM_CONST.HTTP_METHOD_PUT,http_method="REBIND", XDM_CONST.HTTP_METHOD_REBIND,http_method="REPORT", XDM_CONST.HTTP_METHOD_REPORT,http_method="SEARCH", XDM_CONST.HTTP_METHOD_SEARCH,http_method="TRACE", XDM_CONST.HTTP_METHOD_TRACE,http_method="UNBIND", XDM_CONST.HTTP_METHOD_UNBIND,http_method="UNCHECKOUT", XDM_CONST.HTTP_METHOD_UNCHECKOUT,http_method="UNLINK", XDM_CONST.HTTP_METHOD_UNLINK,http_method="UNLOCK", XDM_CONST.HTTP_METHOD_UNLOCK,http_method="UPDATE", XDM_CONST.HTTP_METHOD_UPDATE,http_method="UPDATEREDIRECTREF", XDM_CONST.HTTP_METHOD_UPDATEREDIRECTREF,http_method="VERSION_CONTROL", XDM_CONST.HTTP_METHOD_VERSION_CONTROL, http_method)),
    xdm.network.http.referrer = if(is_network_story=True, http_referer),
    xdm.network.http.response_code = if(is_network_story=True, if(http_status_code=100, XDM_CONST.HTTP_RSP_CODE_CONTINUE,http_status_code=101, XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS,http_status_code=102, XDM_CONST.HTTP_RSP_CODE_PROCESSING,http_status_code=103, XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS,http_status_code=200, XDM_CONST.HTTP_RSP_CODE_OK,http_status_code=201, XDM_CONST.HTTP_RSP_CODE_CREATED,http_status_code=202, XDM_CONST.HTTP_RSP_CODE_ACCEPTED,http_status_code=203, XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION,http_status_code=204, XDM_CONST.HTTP_RSP_CODE_NO_CONTENT,http_status_code=205, XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT,http_status_code=206, XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT,http_status_code=207, XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS,http_status_code=208, XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED,http_status_code=226, XDM_CONST.HTTP_RSP_CODE_IM_USED,http_status_code=300, XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES,http_status_code=301, XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY,http_status_code=302, XDM_CONST.HTTP_RSP_CODE_FOUND,http_status_code=303, XDM_CONST.HTTP_RSP_CODE_SEE_OTHER,http_status_code=304, XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED,http_status_code=305, XDM_CONST.HTTP_RSP_CODE_USE_PROXY,http_status_code=307, XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT,http_status_code=308, XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT,http_status_code=400, XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST,http_status_code=401, XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED,http_status_code=402, XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED,http_status_code=403, XDM_CONST.HTTP_RSP_CODE_FORBIDDEN,http_status_code=404, XDM_CONST.HTTP_RSP_CODE_NOT_FOUND,http_status_code=405, XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED,http_status_code=406, XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE,http_status_code=407, XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED,http_status_code=408, XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT,http_status_code=409, XDM_CONST.HTTP_RSP_CODE_CONFLICT,http_status_code=410, XDM_CONST.HTTP_RSP_CODE_GONE,http_status_code=411, XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED,http_status_code=412, XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED,http_status_code=413, XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE,http_status_code=414, XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG,http_status_code=415, XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE,http_status_code=416, XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE,http_status_code=417, XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED,http_status_code=421, XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST,http_status_code=422, XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT,http_status_code=423, XDM_CONST.HTTP_RSP_CODE_LOCKED,http_status_code=424, XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY,http_status_code=425, XDM_CONST.HTTP_RSP_CODE_TOO_EARLY,http_status_code=426, XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED,http_status_code=428, XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED,http_status_code=429, XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS,http_status_code=431, XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE,http_status_code=451, XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS,http_status_code=500, XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR,http_status_code=501, XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED,http_status_code=502, XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY,http_status_code=503, XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE,http_status_code=504, XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT,http_status_code=505, XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED,http_status_code=506, XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES,http_status_code=507, XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE,http_status_code=508, XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED,http_status_code=511, XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED, to_string(http_status_code))),
    xdm.network.http.url = if(is_network_story=True, to_json_string(arrayindex(http_data, 0))->http_req_full_url),
    xdm.network.http.url_category = if(is_network_story=True, dst_action_url_category),
    xdm.network.icmp.code = if(is_network_story=True, icmp_code),
    xdm.network.icmp.type = if(is_network_story=True, icmp_type),
    xdm.network.ip_protocol = if(is_network_story=True, if(action_network_protocol=ENUM.ICMP, XDM_CONST.IP_PROTOCOL_ICMP, action_network_protocol=ENUM.TCP, XDM_CONST.IP_PROTOCOL_TCP, action_network_protocol=ENUM.UDP, XDM_CONST.IP_PROTOCOL_UDP, to_string(action_network_protocol))),
    xdm.network.ldap.attributes = if(is_network_story=True, ldap_data->attributes[]),
    xdm.network.ldap.bind_auth_type = if(is_network_story=True, if(ldap_data != null, if(auth_service="simple", XDM_CONST.LDAP_BIND_AUTH_TYPE_SIMPLE,auth_service="sasl", XDM_CONST.LDAP_BIND_AUTH_TYPE_SASL, auth_service))),
    xdm.network.ldap.filter = if(is_network_story=True, json_extract_scalar(ldap_data, "$.filter")),
    xdm.network.ldap.operation = if(is_network_story=True, if(ldap_operation="BindRequest", XDM_CONST.LDAP_OPERATION_BIND_REQUEST,ldap_operation="BindResponse", XDM_CONST.LDAP_OPERATION_BIND_RESPONSE,ldap_operation="UnbindRequest", XDM_CONST.LDAP_OPERATION_UNBIND_REQUEST,ldap_operation="SearchRequest", XDM_CONST.LDAP_OPERATION_SEARCH_REQUEST,ldap_operation="SearchResultEntry", XDM_CONST.LDAP_OPERATION_SEARCH_RESULT_ENTRY,ldap_operation="SearchResultDone", XDM_CONST.LDAP_OPERATION_SEARCH_RESULT_DONE,ldap_operation="ModifyRequest", XDM_CONST.LDAP_OPERATION_MODIFY_REQUEST,ldap_operation="ModifyResponse", XDM_CONST.LDAP_OPERATION_MODIFY_RESPONSE,ldap_operation="AddRequest", XDM_CONST.LDAP_OPERATION_ADD_REQUEST,ldap_operation="AddResponse", XDM_CONST.LDAP_OPERATION_ADD_RESPONSE,ldap_operation="DelRequest", XDM_CONST.LDAP_OPERATION_DEL_REQUEST,ldap_operation="DelResponse", XDM_CONST.LDAP_OPERATION_DEL_RESPONSE,ldap_operation="ModifyDNRequest", XDM_CONST.LDAP_OPERATION_MODIFY_DN_REQUEST,ldap_operation="ModifyDNResponse", XDM_CONST.LDAP_OPERATION_MODIFY_DN_RESPONSE,ldap_operation="CompareRequest", XDM_CONST.LDAP_OPERATION_COMPARE_REQUEST,ldap_operation="CompareResponse", XDM_CONST.LDAP_OPERATION_COMPARE_RESPONSE,ldap_operation="AbandonRequest", XDM_CONST.LDAP_OPERATION_ABANDON_REQUEST,ldap_operation="SearchResultReference", XDM_CONST.LDAP_OPERATION_SEARCH_RESULT_REFERENCE,ldap_operation="ExtendedRequest", XDM_CONST.LDAP_OPERATION_EXTENDED_REQUEST,ldap_operation="ExtendedResponse", XDM_CONST.LDAP_OPERATION_EXTENDED_RESPONSE,ldap_operation)),
    xdm.network.ldap.returned_entries = if(is_network_story=True, to_integer(ldap_data->returned_entries)),
    xdm.network.ldap.scope = if(is_network_story=True, if(ldap_scope="baseObject", XDM_CONST.LDAP_SCOPE_BASE_OBJECT, ldap_scope="singleLevel", XDM_CONST.LDAP_SCOPE_SINGLE_LEVEL, ldap_scope="wholeSubtree", XDM_CONST.LDAP_SCOPE_WHOLE_SUBTREE, to_string(ldap_scope))),
    xdm.network.protocol_layers = if(is_network_story=True, action_app_id_transitions),
    xdm.network.rule = if(is_network_story=True, backtrace_identities->rule),
    xdm.network.session_id = story_id,
    xdm.network.tls.client_ja3 = if(is_network_story=True, ssl_data->ja3),
    xdm.network.tls.server_ja3 = if(is_network_story=True, ssl_data->ja3s),
    xdm.network.tls.server_name = if(is_network_story=True, to_json_string(ssl_data)->sni),
    xdm.observer.action = if(is_network_story=True, to_string(backtrace_identities->action)),
    xdm.observer.content_version = if(is_network_story=True, backtrace_identities->content_version),
    xdm.observer.name = if(is_vpn_story=True, vpn_server),
    xdm.observer.product = _product,
    xdm.observer.unique_identifier = backtrace_identities->serial,
    xdm.observer.vendor = _vendor,
    xdm.observer.version = to_string(story_version),
    xdm.session_context_id = story_id,
    xdm.source.agent.content_version = if(is_network_story=True, agent_content_version),
    xdm.source.agent.identifier = if(is_network_story=True, agent_id),
    xdm.source.agent.type = if(is_network_story=True, if(agent_install_type=ENUM.STANDARD, XDM_CONST.AGENT_TYPE_REGULAR, agent_install_type in (ENUM.VDI, ENUM.VDI_GOLDEN), XDM_CONST.AGENT_TYPE_VDI, agent_install_type in (ENUM.TEMPORARY_SESSION, ENUM.DATA_COLLECTOR), XDM_CONST.AGENT_TYPE_COLLECTOR, to_string(agent_install_type))),
    xdm.source.agent.version = if(is_network_story=True, agent_version),
    xdm.source.application.version = if(is_vpn_story=True, client_version_str),
    xdm.source.asn.as_name = action_as_data->organization,
    xdm.source.asn.as_number = action_as_data->as_number,
    xdm.source.host.device_category = if(is_auth_story=True or is_vpn_story=True, auth_client_type, device_id->category),
    xdm.source.host.device_id = if(is_auth_story=True or is_vpn_story=True, if(association_strength > 10, agent_id), device_id->mac),
    xdm.source.host.device_model = if(is_network_story=True, device_id->model),
    xdm.source.host.fqdn = if(is_auth_story=True or is_network_story=True, action_external_hostname),
    xdm.source.host.hardware_uuid = if(is_vpn_story=True or is_auth_story= True, hardware_id),
    xdm.source.host.hostname = if(is_auth_story=True, auth_client, is_vpn_story=True, agent_hostname, agent_hostname),
    xdm.source.host.ipv4_addresses = if(is_auth_story=True or is_vpn_story=True, if(auth_client != null, arraycreate(auth_client)), split(agent_ip_addresses, ",")),
    xdm.source.host.ipv6_addresses = if(is_network_story=True,split(agent_ip_addresses_v6, ",")),
    xdm.source.host.mac_addresses = if(is_auth_story=True or is_vpn_story=True, if(associated_mac != null, arraycreate(associated_mac)), arraymap(agent_interface_map, "@element"->mac)),
    xdm.source.host.manufacturer = if(is_network_story=True, device_id->vendor),
    xdm.source.host.os = agent_os_sub_type,
    xdm.source.host.os_family = if(is_auth_story=True or is_vpn_story=True, if(agent_os_sub_type contains "Windows", XDM_CONST.OS_FAMILY_WINDOWS, agent_os_sub_type contains "Linux", XDM_CONST.OS_FAMILY_LINUX, agent_os_sub_type contains "Mac" or agent_os_sub_type contains "OS X", XDM_CONST.OS_FAMILY_MACOS, agent_os_sub_type contains "iOS", XDM_CONST.OS_FAMILY_IOS, agent_os_sub_type contains "Android", XDM_CONST.OS_FAMILY_ANDROID, agent_os_sub_type), if(agent_os_type=ENUM.AGENT_OS_WINDOWS, XDM_CONST.OS_FAMILY_WINDOWS, agent_os_type=ENUM.AGENT_OS_MAC, XDM_CONST.OS_FAMILY_MACOS,  agent_os_type=ENUM.AGENT_OS_LINUX, XDM_CONST.OS_FAMILY_LINUX, to_string(agent_os_type))),
    xdm.source.interface = if(is_network_story=True, associated_mac),
    xdm.source.ipv4 = if(is_auth_story=True, if(action_local_ip != "", action_local_ip), is_vpn_story=True, auth_client, action_network_is_ipv6=False, if(action_local_ip != "", action_local_ip)),
    xdm.source.ipv6 = if(is_network_story=True, if(action_network_is_ipv6=True, if(action_local_ip != "", action_local_ip))),
    xdm.source.is_internal_ip = is_internal_ip,
    xdm.source.location.city = action_location->city,
    xdm.source.location.continent = action_location->continent,
    xdm.source.location.country = if(action_location->country != "-", action_location->country),
    xdm.source.location.latitude = action_location->latitude,
    xdm.source.location.longitude = action_location->longitude,
    xdm.source.location.region = action_location->region,
    xdm.source.location.timezone = json_extract_scalar(to_json_string(action_location), "$.timezone"),
    xdm.source.port = if(is_auth_story=True or is_network_story=True, if(action_local_port != 0, action_local_port)),
    xdm.source.process.causality_id = if(is_network_story=True, os_actor_process_causality_id),
    xdm.source.process.command_line = if(is_network_story=True, actor_process_command_line),
    xdm.source.process.container_id = if(is_network_story=True, actor_container_info->id),
    xdm.source.process.executable.directory = if(is_network_story=True, if(actor_process_image_path contains "/", arrayindex(split(actor_process_image_path, "/"), -2), actor_process_image_path contains """\\""",  arrayindex(split(actor_process_image_path, "\"), -2), actor_process_image_path)),
    xdm.source.process.executable.extension = if(is_network_story=True, actor_process_image_extension),
    xdm.source.process.executable.file_type = if(is_network_story=True, arrayindex(split(actor_process_image_path, "."), -1)),
    xdm.source.process.executable.filename = if(is_network_story=True, actor_process_image_name),
    xdm.source.process.executable.is_signed = if(is_network_story=True, if(actor_process_signature_status in (ENUM.SIGNED, ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601))),
    xdm.source.process.executable.md5 = if(is_network_story=True, actor_process_image_md5),
    xdm.source.process.executable.path = if(is_network_story=True, actor_process_image_path),
    xdm.source.process.executable.sha256 = if(is_network_story=True, actor_process_image_sha256),
    xdm.source.process.executable.signature_status = if(is_network_story=True, if(actor_process_signature_status=ENUM.SIGNED, XDM_CONST.SIGNATURE_STATUS_SIGNED_VERIFIED, actor_process_signature_status in (ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601), XDM_CONST.SIGNATURE_STATUS_SIGNED_INVALID, actor_process_signature_status=ENUM.UNSIGNED, XDM_CONST.SIGNATURE_STATUS_UNSIGNED, XDM_CONST.SIGNATURE_STATUS_STATUS_UNKNOWN)),
    xdm.source.process.executable.signer = if(is_network_story=True, actor_process_signature_vendor),
    xdm.source.process.identifier = if(is_network_story=True, actor_process_instance_id),
    xdm.source.process.integrity_level = if(is_network_story=True, actor_process_integrity_level),
    xdm.source.process.is_injected = if(is_network_story=True, actor_is_injected_thread),
    xdm.source.process.name = if(is_network_story=True, actor_process_image_name),
    xdm.source.process.pid = if(is_network_story=True, actor_process_os_pid),
    xdm.source.process.thread_id = if(is_network_story=True, actor_thread_thread_id),
    xdm.source.sent_bytes = if(is_network_story=True, action_total_upload),
    xdm.source.sent_packets = if(is_network_story=True, action_pkts_sent),
    xdm.source.identity.domain = if(is_vpn_story=True or is_network_story=True, auth_domain),
    xdm.source.identity.identifier = if(is_network_story=True, actor_primary_user_sid),
    xdm.source.identity.identity_type = if(is_vpn_story=True, auth_normalized_user->identity_type),
    xdm.source.identity.netbios_domain = if(is_auth_story=True, auth_normalized_user->domain),
    xdm.source.identity.sam_account_name = if(is_auth_story=True, auth_normalized_user->username),
    xdm.source.identity.scope = if(is_auth_story=True, auth_normalized_user->scope),
    xdm.source.identity.upn = if(is_auth_story=True, auth_normalized_user->upn),
    xdm.source.identity.user_type = if(is_vpn_story=True, auth_normalized_user->identity_type),
    xdm.source.identity.username = if(is_vpn_story=True, auth_identity, is_network_story=True, coalesce(auth_identity, actor_primary_username)),
    xdm.source.user_agent = action_user_agent,
    xdm.source.zone = if(is_network_story=True, backtrace_identities->interface_from),
    xdm.target.agent.content_version = if(is_network_story=True, dst_agent_content_version),
    xdm.target.agent.identifier = if(is_network_story=True, dst_agent_id),
    xdm.target.agent.type = if(is_network_story=True, if(dst_agent_install_type=ENUM.STANDARD, XDM_CONST.AGENT_TYPE_REGULAR, dst_agent_install_type in (ENUM.VDI, ENUM.VDI_GOLDEN), XDM_CONST.AGENT_TYPE_VDI, dst_agent_install_type in (ENUM.TEMPORARY_SESSION, ENUM.DATA_COLLECTOR), XDM_CONST.AGENT_TYPE_COLLECTOR, to_string(dst_agent_install_type))),
    xdm.target.agent.version = if(is_network_story=True, dst_agent_version),
    xdm.target.application.name = if(is_vpn_story=True, coalesce(checkpoint_vpn_data->client_application, vpn_service)),
    xdm.target.asn.as_name = if(is_network_story=True, dst_action_as_data->organization),
    xdm.target.asn.as_number = if(is_network_story=True, dst_action_as_data->as_number),
    xdm.target.domain = if(is_auth_story=True, auth_normalized_user->domain),
    xdm.target.file.extension = if(is_network_story=True, file_data->file_extension),
    xdm.target.file.file_type = if(is_network_story=True, file_data->file_type),
    xdm.target.file.filename = if(is_network_story=True, file_data->file_name),
    xdm.target.file.path = if(is_network_story=True, file_data->file_url),
    xdm.target.file.sha256 = if(is_network_story=True, file_data->file_sha_256),
    xdm.target.host.device_category = if(is_network_story=True, dst_device_id->category),
    xdm.target.host.device_id = if(is_auth_story=True, if(is_ntlm_story=True, if(association_strength > 10, agent_id), is_vpn_story=True, if(dst_association_strength > 10, dst_agent_id)), dst_device_id->mac),
    xdm.target.host.device_model = if(is_network_story=True, dst_device_id->model),
    xdm.target.host.fqdn = if(is_network_story=True, dst_action_external_hostname),
    xdm.target.host.hostname = if(is_auth_story=True, auth_target, is_vpn_story=True, dst_agent_hostname, dst_agent_hostname),
    xdm.target.host.ipv4_addresses = if(is_auth_story=True, if(is_ntlm_story=True, split(agent_ip_addresses, ",")), is_vpn_story=True, if(action_remote_ip != null, arraycreate(action_remote_ip)), is_network_story=True, split(dst_agent_ip_addresses, ",")),
    xdm.target.host.ipv6_addresses = if(is_auth_story=True, if(is_ntlm_story=True, split(agent_ip_addresses_v6, ",")), is_network_story=True, split(dst_agent_ip_addresses_v6, ",")),
    xdm.target.host.mac_addresses = if(is_auth_story=True, if(is_ntlm_story=True, arraymap(agent_interface_map, "@element"->mac)), is_vpn_story=True, if(dst_associated_mac != null, arraycreate(dst_associated_mac)), arraymap(dst_agent_interface_map, "@element"->mac)),
    xdm.target.host.manufacturer = if(is_network_story=True, dst_device_id->vendor),
    xdm.target.host.os = if(is_network_story=True, dst_agent_os_sub_type),
    xdm.target.host.os_family = if(is_network_story=True, if(dst_agent_os_type=ENUM.AGENT_OS_WINDOWS, XDM_CONST.OS_FAMILY_WINDOWS, dst_agent_os_type=ENUM.AGENT_OS_MAC, XDM_CONST.OS_FAMILY_MACOS,  dst_agent_os_type=ENUM.AGENT_OS_LINUX, XDM_CONST.OS_FAMILY_LINUX, to_string(dst_agent_os_type))),
    xdm.target.interface = if(is_network_story=True, dst_associated_mac),
    xdm.target.ipv4 =  if(action_network_is_ipv6=False, if(action_proxy=True, dst_action_external_hostname_as_ip, if(is_kerberos_story!=True, if(action_remote_ip != "", action_remote_ip), is_network_story=True, if(action_remote_ip != "", action_remote_ip)))),
    xdm.target.ipv6 = if(action_network_is_ipv6=True, if(action_proxy=True, dst_action_external_hostname_as_ip, if(is_network_story=True, if(action_remote_ip != "", action_remote_ip)))),
    xdm.target.is_internal_ip =  if(action_proxy=False, dst_is_internal_ip),
    xdm.target.location.city = if(is_network_story=True, dst_action_location->city),
    xdm.target.location.continent = if(is_network_story=True, dst_action_location->continent),
    xdm.target.location.country = if(is_network_story=True, if(dst_action_location->country != "-", dst_action_location->country)),
    xdm.target.location.latitude = if(is_network_story=True, dst_action_location->latitude),
    xdm.target.location.longitude = if(is_network_story=True, dst_action_location->longitude),
    xdm.target.location.region = if(is_network_story=True, dst_action_location->region),
    xdm.target.location.timezone = if(is_network_story=True, json_extract_scalar(to_json_string(dst_action_location), "$.timezone")),
    xdm.target.port = if(action_proxy=True, action_external_port, if(is_kerberos_story!=True, if(action_remote_port != 0, action_remote_port))),
    xdm.target.process.causality_id = if(is_network_story=True, dst_os_actor_process_causality_id),
    xdm.target.process.command_line = if(is_network_story=True, dst_actor_process_command_line),
    xdm.target.process.container_id = if(is_network_story=True, dst_actor_container_info->id),
    xdm.target.process.executable.directory = if(is_network_story=True, if(dst_actor_process_image_path contains "/", arrayindex(split(dst_actor_process_image_path, "/"), -2), dst_actor_process_image_path contains """\\""",  arrayindex(split(dst_actor_process_image_path, "\"), -2), dst_actor_process_image_path)),
    xdm.target.process.executable.extension = if(is_network_story=True, dst_actor_process_image_extension),
    xdm.target.process.executable.file_type = if(is_network_story=True, arrayindex(split(dst_actor_process_image_path, "."), -1)),
    xdm.target.process.executable.filename = if(is_network_story=True, dst_actor_process_image_name),
    xdm.target.process.executable.is_signed = if(is_network_story=True, if(dst_actor_process_signature_status in (ENUM.SIGNED, ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601))),
    xdm.target.process.executable.md5 = if(is_network_story=True, dst_actor_process_image_md5),
    xdm.target.process.executable.path = if(is_network_story=True, dst_actor_process_image_path),
    xdm.target.process.executable.sha256 = if(is_network_story=True, dst_actor_process_image_sha256),
    xdm.target.process.executable.signature_status = if(is_network_story=True, if(dst_actor_process_signature_status=ENUM.SIGNED, XDM_CONST.SIGNATURE_STATUS_SIGNED_VERIFIED, dst_actor_process_signature_status in (ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601), XDM_CONST.SIGNATURE_STATUS_SIGNED_INVALID, dst_actor_process_signature_status=ENUM.UNSIGNED, XDM_CONST.SIGNATURE_STATUS_UNSIGNED, XDM_CONST.SIGNATURE_STATUS_STATUS_UNKNOWN)),
    xdm.target.process.executable.signer = if(is_network_story=True, dst_actor_process_signature_vendor),
    xdm.target.process.identifier = if(is_network_story=True, dst_actor_process_instance_id),
    xdm.target.process.integrity_level = if(is_network_story=True, dst_actor_process_integrity_level),
    xdm.target.process.is_injected = if(is_network_story=True, dst_actor_is_injected_thread),
    xdm.target.process.name = if(is_network_story=True, dst_actor_process_image_name),
    xdm.target.process.pid = if(is_network_story=True, dst_actor_process_os_pid),
    xdm.target.process.thread_id = if(is_network_story=True, dst_actor_thread_thread_id),
    xdm.target.sent_bytes = if(is_network_story=True, action_total_download),
    xdm.target.sent_packets = if(is_network_story=True, action_pkts_received),
    xdm.target.identity.domain = if(is_auth_story=True, auth_domain),
    xdm.target.identity.identifier = if(is_network_story=True, dst_actor_primary_user_sid),
    xdm.target.identity.identity_type = if(is_auth_story=True, auth_normalized_user->identity_type),
    xdm.target.identity.netbios_domain = if(is_auth_story=True, auth_normalized_user->domain),
    xdm.target.identity.sam_account_name = if(is_auth_story=True, auth_normalized_user->username),
    xdm.target.identity.scope = if(is_auth_story=True, auth_normalized_user->scope),
    xdm.target.identity.upn = if(is_auth_story=True, auth_normalized_user->upn),
    xdm.target.identity.user_type = if(is_auth_story=True, auth_normalized_user->identity_type),
    xdm.target.identity.username = if(is_auth_story=True, auth_identity, is_network_story=True, dst_actor_primary_username),
    xdm.target.zone = if(is_network_story=True, backtrace_identities->interface_to);

// Union with Endpoint mapping
filter
    event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY, ENUM.LOAD_IMAGE)
| alter
    action_module_path_parts = if(action_module_path contains "/", split(action_module_path, "/"), action_module_path contains """\\""", split(action_module_path, """\\""")),
    agent_interface_map = to_json_string(agent_interface_map)->[]
| alter
    _insert_time = insert_timestamp,
    xdm.event.id = event_id,
    xdm.event.operation = if(event_type=ENUM.PROCESS, if(event_sub_type=ENUM.PROCESS_START, XDM_CONST.OPERATION_TYPE_PROCESS_CREATE, event_sub_type=ENUM.PROCESS_STOP, XDM_CONST.OPERATION_TYPE_PROCESS_TERMINATE, to_string(event_sub_type)), event_type=ENUM.FILE, if(event_sub_type=ENUM.FILE_CREATE_NEW, XDM_CONST.OPERATION_TYPE_FILE_CREATE, event_sub_type=ENUM.FILE_OPEN, XDM_CONST.OPERATION_TYPE_FILE_OPEN, event_sub_type=ENUM.FILE_RENAME, XDM_CONST.OPERATION_TYPE_FILE_RENAME, event_sub_type=ENUM.FILE_LINK, XDM_CONST.OPERATION_TYPE_FILE_LINK, event_sub_type=ENUM.FILE_REMOVE, XDM_CONST.OPERATION_TYPE_FILE_REMOVE, event_sub_type=ENUM.FILE_WRITE, XDM_CONST.OPERATION_TYPE_FILE_WRITE, event_sub_type=ENUM.FILE_SET_ATTRIBUTE, XDM_CONST.OPERATION_TYPE_FILE_SET_ATTRIBUTES,event_sub_type=ENUM.FILE_DIR_CREATE, XDM_CONST.OPERATION_TYPE_DIR_CREATE, event_sub_type=ENUM.FILE_DIR_OPEN, XDM_CONST.OPERATION_TYPE_DIR_OPEN, event_sub_type=ENUM.FILE_DIR_RENAME, XDM_CONST.OPERATION_TYPE_DIR_RENAME, event_sub_type=ENUM.FILE_DIR_LINK, XDM_CONST.OPERATION_TYPE_DIR_LINK, event_sub_type=ENUM.FILE_DIR_REMOVE, XDM_CONST.OPERATION_TYPE_DIR_REMOVE, event_sub_type=ENUM.FILE_DIR_WRITE, XDM_CONST.OPERATION_TYPE_DIR_WRITE, event_sub_type=ENUM.FILE_DIR_SET_ATTR, XDM_CONST.OPERATION_TYPE_DIR_SET_ATTRIBUTES, event_sub_type=ENUM.FILE_REPARSE, XDM_CONST.OPERATION_TYPE_FILE_REPARSE, event_sub_type=ENUM.FILE_SET_SECURITY_DESCRIPTOR, XDM_CONST.OPERATION_TYPE_FILE_SET_SECURITY, event_sub_type=17, XDM_CONST.OPERATION_TYPE_DIR_SET_SECURITY, event_sub_type=ENUM.FILE_CHANGE_MODE, XDM_CONST.OPERATION_TYPE_FILE_CHANGE_MODE, event_sub_type=ENUM.FILE_DIR_CHANGE_MODE, XDM_CONST.OPERATION_TYPE_DIR_CHANGE_MODE, event_sub_type=ENUM.FILE_CHANGE_OWNER, XDM_CONST.OPERATION_TYPE_FILE_CHANGE_OWNER, event_sub_type=ENUM.FILE_DIR_CHANGE_OWNER, XDM_CONST.OPERATION_TYPE_DIR_CHANGE_OWNER, event_sub_type=ENUM.FILE_DIR_QUERY, XDM_CONST.OPERATION_TYPE_DIR_QUERY, event_sub_type=ENUM.FILE_DELETE_EXT_ATTRIBUTE, XDM_CONST.OPERATION_TYPE_FILE_DELETE_EXT_ATTRIBUTES,  event_sub_type=24, XDM_CONST.OPERATION_TYPE_FILE_STATS,  event_sub_type=25, XDM_CONST.OPERATION_TYPE_DIR_STATS,  to_string(event_sub_type)), event_type=ENUM.REGISTRY, if(event_sub_type=ENUM.REGISTRY_CREATE_KEY, XDM_CONST.OPERATION_TYPE_REGISTRY_CREATE_KEY, event_sub_type=ENUM.REGISTRY_DELETE_KEY, XDM_CONST.OPERATION_TYPE_REGISTRY_DELETE_KEY, event_sub_type=ENUM.REGISTRY_RENAME_KEY, XDM_CONST.OPERATION_TYPE_REGISTRY_RENAME_KEY, event_sub_type=ENUM.REGISTRY_SET_VALUE, XDM_CONST.OPERATION_TYPE_REGISTRY_SET_VALUE, event_sub_type=ENUM.REGISTRY_DELETE_VALUE, XDM_CONST.OPERATION_TYPE_REGISTRY_DELETE_VALUE, event_sub_type=ENUM.REGISTRY_LOAD, XDM_CONST.OPERATION_TYPE_REGISTRY_LOAD, event_sub_type=ENUM.REGISTRY_UNLOAD, XDM_CONST.OPERATION_TYPE_REGISTRY_UNLOAD, event_sub_type=ENUM.REGISTRY_SAVE, XDM_CONST.OPERATION_TYPE_REGISTRY_SAVE, event_sub_type=ENUM.REGISTRY_RESTORE, XDM_CONST.OPERATION_TYPE_REGISTRY_RESTORE, event_sub_type=10, XDM_CONST.OPERATION_TYPE_REGISTRY_OPEN, event_sub_type=11, XDM_CONST.OPERATION_TYPE_REGISTRY_QUERY_VALUE, to_string(event_sub_type)), event_type=ENUM.LOAD_IMAGE, if(event_sub_type=ENUM.LOAD_IMAGE_MODULE, XDM_CONST.OPERATION_TYPE_IMAGE_LOAD, event_sub_type=ENUM.LOAD_IMAGE_MPROTECT, XDM_CONST.OPERATION_TYPE_IMAGE_MPROTECT, event_sub_type=ENUM.LOAD_IMAGE_PRELOAD, XDM_CONST.OPERATION_TYPE_IMAGE_PRE_LOAD, event_sub_type=4, XDM_CONST.OPERATION_TYPE_IMAGE_UNLOAD, event_sub_type=ENUM.LOAD_IMAGE_SO_LOAD, XDM_CONST.OPERATION_TYPE_IMAGE_SO_LOAD, to_string(event_sub_type))),
    xdm.event.operation_sub_type = to_string(event_sub_type),
    xdm.event.outcome = if(event_type=ENUM.PROCESS, if(action_process_termination_code!=0, XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_SUCCESS), event_type=ENUM.REGISTRY, if(action_registry_return_val = 0, XDM_CONST.OUTCOME_SUCCESS, action_registry_return_val > 0, XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN)),
    xdm.event.type = to_string(event_type),
    xdm.observer.content_version = agent_content_version,
    xdm.observer.name = agent_hostname,
    xdm.observer.product = _product,
    xdm.observer.type = if(agent_install_type=ENUM.STANDARD, "AGENT_TYPE_REGULAR", agent_install_type in (ENUM.VDI, ENUM.VDI_GOLDEN), "AGENT_TYPE_VDI", agent_install_type in (ENUM.TEMPORARY_SESSION, ENUM.DATA_COLLECTOR), "AGENT_TYPE_COLLECTOR", to_string(agent_install_type)),
    xdm.observer.unique_identifier = agent_id,
    xdm.observer.vendor = _vendor,
    xdm.observer.version = agent_version,
    xdm.session_context_id = action_network_connection_id,
    xdm.source.agent.content_version = agent_content_version,
    xdm.source.agent.identifier = agent_id,
    xdm.source.agent.type = if(agent_install_type=ENUM.STANDARD, XDM_CONST.AGENT_TYPE_REGULAR, agent_install_type in (ENUM.VDI, ENUM.VDI_GOLDEN), XDM_CONST.AGENT_TYPE_VDI, agent_install_type in (ENUM.TEMPORARY_SESSION, ENUM.DATA_COLLECTOR), XDM_CONST.AGENT_TYPE_COLLECTOR, to_string(agent_install_type)),
    xdm.source.agent.version = agent_version,
    xdm.source.host.device_id = agent_id,
    xdm.source.host.hostname = agent_hostname,
    xdm.source.host.ipv4_addresses = split(agent_ip_addresses, ","),
    xdm.source.host.ipv6_addresses = split(agent_ip_addresses_v6, ","),
    xdm.source.host.mac_addresses = arraymap(agent_interface_map, "@element"->mac),
    xdm.source.host.os = agent_os_sub_type,
    xdm.source.host.os_family = if(agent_os_type=ENUM.AGENT_OS_WINDOWS, XDM_CONST.OS_FAMILY_WINDOWS, agent_os_type=ENUM.AGENT_OS_MAC, XDM_CONST.OS_FAMILY_MACOS,  agent_os_type=ENUM.AGENT_OS_LINUX, XDM_CONST.OS_FAMILY_LINUX),
    xdm.source.process.causality_id = actor_process_causality_id,
    xdm.source.process.command_line = actor_process_command_line,
    xdm.source.process.container_id = actor_process_container_id,
    xdm.source.process.executable.extension = actor_process_image_extension,
    xdm.source.process.executable.file_type = if(action_file_type=0, "Unknown", action_file_type=1, "MZ(executable)", action_file_type=2, "PK(Zipfile)", action_file_type=3, "OLE(CompoundDocument)", action_file_type=4, "RAR", action_file_type=5, "LNK", action_file_type=6, "PNG", action_file_type=7, "EML", action_file_type=8, "GIF", action_file_type=9, "7ZIP", action_file_type=10, "RTF", action_file_type=11, "PDF", action_file_type=12, "JavaClass", action_file_type=13, "MP3", action_file_type=14, "SWF", action_file_type=15, "GZ", action_file_type=16, "JPG", action_file_type=17, "BMP", action_file_type=18, "NotEvaluated", action_file_type=19, "ELF", action_file_type=20, "Mach032", action_file_type=21, "Mach064", action_file_type=22, "Shabang", action_file_type=23, "Rpm", action_file_type=24, "Deb", action_file_type=25, "Tar", action_file_type=26, "Zip", action_file_type=27, "Bz2", action_file_type=28, "Xz", action_file_type=29, "shell", action_file_type=30, "Python", action_file_type=31, "Perl", action_file_type=32, "ShimDb", action_file_type=33, "WinMemDmp", action_file_type=34, "VBE", to_string(action_file_type)),
    xdm.source.process.executable.filename = actor_process_image_name,
    xdm.source.process.executable.is_signed = if(actor_process_signature_status in (ENUM.SIGNED, ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601)),
    xdm.source.process.executable.md5 = actor_process_image_md5,
    xdm.source.process.executable.path = actor_process_image_path,
    xdm.source.process.executable.sha256 = actor_process_image_sha256,
    xdm.source.process.executable.signature_status = if(actor_process_signature_status=ENUM.SIGNED, XDM_CONST.SIGNATURE_STATUS_SIGNED_VERIFIED, actor_process_signature_status in (ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601), XDM_CONST.SIGNATURE_STATUS_SIGNED_INVALID, actor_process_signature_status=ENUM.UNSIGNED, XDM_CONST.SIGNATURE_STATUS_UNSIGNED, XDM_CONST.SIGNATURE_STATUS_STATUS_UNKNOWN),
    xdm.source.process.executable.signer = actor_process_signature_vendor,
    xdm.source.process.identifier = actor_process_instance_id,
    xdm.source.process.integrity_level = actor_process_integrity_level,
    xdm.source.process.is_injected = actor_is_injected_thread,
    xdm.source.process.name = actor_process_image_name,
    xdm.source.process.pid = actor_process_os_pid,
    xdm.source.process.thread_id = actor_thread_thread_id,
    xdm.source.identity.identifier = actor_primary_user_sid,
    xdm.source.identity.username = actor_primary_username,
    xdm.target.file.extension = action_file_extension,
    xdm.target.file.file_type = if(action_file_type=0, "Unknown", action_file_type=1, "MZ(executable)", action_file_type=2, "PK(Zipfile)", action_file_type=3, "OLE(CompoundDocument)", action_file_type=4, "RAR", action_file_type=5, "LNK", action_file_type=6, "PNG", action_file_type=7, "EML", action_file_type=8, "GIF", action_file_type=9, "7ZIP", action_file_type=10, "RTF", action_file_type=11, "PDF", action_file_type=12, "JavaClass", action_file_type=13, "MP3", action_file_type=14, "SWF", action_file_type=15, "GZ", action_file_type=16, "JPG", action_file_type=17, "BMP", action_file_type=18, "NotEvaluated", action_file_type=19, "ELF", action_file_type=20, "Mach032", action_file_type=21, "Mach064", action_file_type=22, "Shabang", action_file_type=23, "Rpm", action_file_type=24, "Deb", action_file_type=25, "Tar", action_file_type=26, "Zip", action_file_type=27, "Bz2", action_file_type=28, "Xz", action_file_type=29, "shell", action_file_type=30, "Python", action_file_type=31, "Perl", action_file_type=32, "ShimDb", action_file_type=33, "WinMemDmp", action_file_type=34, "VBE", to_string(action_file_type)),
    xdm.target.file.filename = action_file_name,
    xdm.target.file.md5 = action_file_md5,
    xdm.target.file.path = action_file_path,
    xdm.target.file.sha256 = action_file_sha256,
    xdm.target.file.signature_status = if(action_file_signature_status=ENUM.SIGNED, XDM_CONST.SIGNATURE_STATUS_SIGNED_VERIFIED, action_file_signature_status in (ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601), XDM_CONST.SIGNATURE_STATUS_SIGNED_INVALID, action_file_signature_status=ENUM.UNSIGNED, XDM_CONST.SIGNATURE_STATUS_UNSIGNED, XDM_CONST.SIGNATURE_STATUS_STATUS_UNKNOWN),
    xdm.target.file.signer = action_file_signature_vendor,
    xdm.target.file_before.extension = action_file_previous_file_extension,
    xdm.target.file_before.file_type = if(action_file_type_prev=0, "Unknown", action_file_type_prev=1, "MZ", action_file_type_prev=2, "PK", action_file_type_prev=3, "OLE", action_file_type_prev=4, "RAR", action_file_type_prev=5, "LNK", action_file_type_prev=6, "PNG", action_file_type_prev=7, "EML", action_file_type_prev=8, "GIF", action_file_type_prev=9, "7ZIP", action_file_type_prev=10, "RTF", action_file_type_prev=11, "PDF", action_file_type_prev=12, "JavaClass", action_file_type_prev=13, "MP3", action_file_type_prev=14, "SWF", action_file_type_prev=15, "GZ", action_file_type_prev=16, "JPG", action_file_type_prev=17, "BMP", action_file_type_prev=18, "NotEvaluated", action_file_type_prev=19, "ELF", action_file_type_prev=20, "Mach032", action_file_type_prev=21, "Mach064", action_file_type_prev=22, "Shabang", action_file_type_prev=23, "Rpm", action_file_type_prev=24, "Deb", action_file_type_prev=25, "Tar", action_file_type_prev=26, "Zip", action_file_type_prev=27, "Bz2", action_file_type_prev=28, "Xz", action_file_type_prev=29, "shell", action_file_type_prev=30, "Python", action_file_type_prev=31, "Perl", action_file_type_prev=32, "ShimDb", action_file_type_prev=33, "WinMemDmp", action_file_type_prev=34, "VBE", to_string(action_file_type_prev)),
    xdm.target.file_before.filename = action_file_previous_file_name,
    xdm.target.file_before.path = action_file_previous_file_path,
    xdm.target.module.directory = arrayindex(action_module_path_parts, -2),
    xdm.target.module.extension = arrayindex(split(arrayindex(action_module_path_parts, -1), "."), -1),
    xdm.target.module.filename = arrayindex(action_module_path_parts, -1),
    xdm.target.module.is_signed = if(action_module_signature_status in (ENUM.SIGNED, ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601)),
    xdm.target.module.md5 = action_module_md5,
    xdm.target.module.path = action_module_path,
    xdm.target.module.sha256 = action_module_sha256,
    xdm.target.module.signature_status = if(action_module_signature_status=ENUM.SIGNED, XDM_CONST.SIGNATURE_STATUS_SIGNED_VERIFIED, action_module_signature_status in (ENUM.SIGNED_INVALID, ENUM.WEAK_HASH, ENUM.INVALID_CVE2020_0601), XDM_CONST.SIGNATURE_STATUS_SIGNED_INVALID, action_module_signature_status=ENUM.UNSIGNED, XDM_CONST.SIGNATURE_STATUS_UNSIGNED, XDM_CONST.SIGNATURE_STATUS_STATUS_UNKNOWN),
    xdm.target.module.signer = action_module_signature_vendor,
    xdm.target.process.causality_id = action_process_causality_id,
    xdm.target.process.command_line = action_process_image_command_line,
    xdm.source.process.executable.directory = if(actor_process_image_path contains "/", arrayindex(split(actor_process_image_path, "/"), -2), actor_process_image_path contains """\\""", arrayindex(split(actor_process_image_path, """\\"""), -2)),
    xdm.target.process.executable.extension = action_process_image_extension,
    xdm.target.process.executable.file_type = if(action_file_type=0, "Unknown", action_file_type=1, "MZ(executable)", action_file_type=2, "PK(Zipfile)", action_file_type=3, "OLE(CompoundDocument)", action_file_type=4, "RAR", action_file_type=5, "LNK", action_file_type=6, "PNG", action_file_type=7, "EML", action_file_type=8, "GIF", action_file_type=9, "7ZIP", action_file_type=10, "RTF", action_file_type=11, "PDF", action_file_type=12, "JavaClass", action_file_type=13, "MP3", action_file_type=14, "SWF", action_file_type=15, "GZ", action_file_type=16, "JPG", action_file_type=17, "BMP", action_file_type=18, "NotEvaluated", action_file_type=19, "ELF", action_file_type=20, "Mach032", action_file_type=21, "Mach064", action_file_type=22, "Shabang", action_file_type=23, "Rpm", action_file_type=24, "Deb", action_file_type=25, "Tar", action_file_type=26, "Zip", action_file_type=27, "Bz2", action_file_type=28, "Xz", action_file_type=29, "shell", action_file_type=30, "Python", action_file_type=31, "Perl", action_file_type=32, "ShimDb", action_file_type=33, "WinMemDmp", action_file_type=34, "VBE", to_string(action_file_type)),
    xdm.target.process.executable.filename = action_process_image_name,
    xdm.target.process.executable.md5 = action_process_image_md5,
    xdm.target.process.executable.path = action_process_image_path,
    xdm.target.process.executable.sha256 = action_process_image_sha256,
    xdm.target.process.identifier = action_process_instance_id,
    xdm.target.process.integrity_level = action_process_integrity_level,
    xdm.target.process.name = action_process_image_name,
    xdm.target.process.parent_id = action_process_requested_parent_iid,
    xdm.target.process.pid = action_process_os_pid,
    xdm.target.registry.data = action_registry_data,
    xdm.target.registry.key = action_registry_key_name,
    xdm.target.registry.value = action_registry_value_name,
    xdm.target.registry.value_type = if(action_registry_value_type=ENUM.TYPE_SZ, XDM_CONST.REGISTRY_VALUE_TYPE_REG_SZ,action_registry_value_type=ENUM.TYPE_EXPAND_SZ, XDM_CONST.REGISTRY_VALUE_TYPE_REG_EXPAND_SZ,action_registry_value_type=ENUM.TYPE_BINARY, XDM_CONST.REGISTRY_VALUE_TYPE_REG_BINARY,action_registry_value_type=ENUM.TYPE_DWORD, XDM_CONST.REGISTRY_VALUE_TYPE_REG_DWORD,action_registry_value_type=ENUM.TYPE_DWORD_BIG_ENDIAN, XDM_CONST.REGISTRY_VALUE_TYPE_REG_DWORD_BIG_ENDIAN,action_registry_value_type=ENUM.TYPE_LINK, XDM_CONST.REGISTRY_VALUE_TYPE_REG_LINK,action_registry_value_type=ENUM.TYPE_MULTI_SZ, XDM_CONST.REGISTRY_VALUE_TYPE_REG_MULTI_SZ,action_registry_value_type=ENUM.TYPE_QWORD, XDM_CONST.REGISTRY_VALUE_TYPE_REG_QWORD, to_string(action_registry_value_type)),
    xdm.target.registry_before.data = action_registry_old_data,
    xdm.target.registry_before.key = action_registry_old_key_name;
/* -------------------------------------
   ------- Marketplace mappings --------
   ------------------------------------- */



[RULE: arista_switch_common_fields_modeling content_id="aristaswitch"]
alter 
    dvc_process_tuple = split(arrayindex(regextract(_raw_log, "<\d+>.+?\s+(\S+\s+\S+):\s+"),0)),
    //seq_num = arrayindex(regextract(_raw_log, "<\d+>.+?\s+\S+\s+\w+: (\d+): \S+: .+"), 0),
    facility_severity_mnemonic_tuple = split(arrayindex(regextract(_raw_log, "%(\S+\-\d\-\w+):"), 0), "-"),
    message = arrayindex(regextract(_raw_log, "<\d+>.+ \S+ \S+: \S+: (.+)"), 0),  

    // extract alternative token for the facility in case it is not in the expected format of %FACILITY-Severity-Mnemonic:
    alternative_facility1 = arrayindex(regextract(_raw_log, "<\d+>.+? \S+ \w+: \d+: %{0,1}(\S+): .+"), 0), //if log includes sequence number 
    alternative_facility2 = arrayindex(regextract(_raw_log, "<\d+>.+? \S+ \w+: %{0,1}(\S+): .+"), 0) // if log does not include a sequence a number
| alter
    dvc = arrayindex(dvc_process_tuple, 0),
    process = arrayindex(dvc_process_tuple, 1), 
    tuple_facility = arrayindex(facility_severity_mnemonic_tuple, 0), 
    severity = arrayindex(facility_severity_mnemonic_tuple, 1), 
    mnemonic = arrayindex(facility_severity_mnemonic_tuple, 2)
| alter 
    facility = coalesce(tuple_facility, alternative_facility1, alternative_facility2)
| alter 
    xdm.observer.name = dvc,
    xdm.observer.type = facility,
    xdm.source.application.name = process,
    xdm.event.id = coalesce(mnemonic, facility),
    xdm.event.type = coalesce(mnemonic, facility),
    xdm.event.description = message,
    xdm.event.log_level = if(severity = "0", XDM_CONST.LOG_LEVEL_EMERGENCY , severity = "1", XDM_CONST.LOG_LEVEL_ALERT , severity = "2", XDM_CONST.LOG_LEVEL_CRITICAL, severity = "3", XDM_CONST.LOG_LEVEL_ERROR, severity = "4", XDM_CONST.LOG_LEVEL_WARNING, severity = "5", XDM_CONST.LOG_LEVEL_NOTICE, severity = "6", XDM_CONST.LOG_LEVEL_INFORMATIONAL, severity = "7", XDM_CONST.LOG_LEVEL_DEBUG, severity),
    xdm.alert.severity = severity;


/* Modeling Rule defintion for mapping the IP protocol field from the syslog payload to its corresponding XDM enum field. */
[RULE: arista_switch_map_ip_protocol content_id="aristaswitch"]
alter xdm.network.ip_protocol = if(ip_proto="HOPOPT",XDM_CONST.IP_PROTOCOL_HOPOPT, ip_proto="ICMP",XDM_CONST.IP_PROTOCOL_ICMP, ip_proto="IGMP",XDM_CONST.IP_PROTOCOL_IGMP, ip_proto="GGP",XDM_CONST.IP_PROTOCOL_GGP, ip_proto="IP",XDM_CONST.IP_PROTOCOL_IP, ip_proto="ST",XDM_CONST.IP_PROTOCOL_ST, ip_proto="TCP",XDM_CONST.IP_PROTOCOL_TCP, ip_proto="CBT",XDM_CONST.IP_PROTOCOL_CBT, ip_proto="EGP",XDM_CONST.IP_PROTOCOL_EGP, ip_proto="IGP",XDM_CONST.IP_PROTOCOL_IGP, ip_proto="BBN_RCC_MON",XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, ip_proto="NVP_II",XDM_CONST.IP_PROTOCOL_NVP_II, ip_proto="PUP",XDM_CONST.IP_PROTOCOL_PUP, ip_proto="ARGUS",XDM_CONST.IP_PROTOCOL_ARGUS, ip_proto="EMCON",XDM_CONST.IP_PROTOCOL_EMCON, ip_proto="XNET",XDM_CONST.IP_PROTOCOL_XNET, ip_proto="CHAOS",XDM_CONST.IP_PROTOCOL_CHAOS, ip_proto="UDP",XDM_CONST.IP_PROTOCOL_UDP, ip_proto="MUX",XDM_CONST.IP_PROTOCOL_MUX, ip_proto="DCN_MEAS",XDM_CONST.IP_PROTOCOL_DCN_MEAS, ip_proto="HMP",XDM_CONST.IP_PROTOCOL_HMP, ip_proto="PRM",XDM_CONST.IP_PROTOCOL_PRM, ip_proto="XNS_IDP",XDM_CONST.IP_PROTOCOL_XNS_IDP, ip_proto="TRUNK_1",XDM_CONST.IP_PROTOCOL_TRUNK_1, ip_proto="TRUNK_2",XDM_CONST.IP_PROTOCOL_TRUNK_2, ip_proto="LEAF_1",XDM_CONST.IP_PROTOCOL_LEAF_1, ip_proto="LEAF_2",XDM_CONST.IP_PROTOCOL_LEAF_2, ip_proto="RDP",XDM_CONST.IP_PROTOCOL_RDP, ip_proto="IRTP",XDM_CONST.IP_PROTOCOL_IRTP, ip_proto="ISO_TP4",XDM_CONST.IP_PROTOCOL_ISO_TP4, ip_proto="NETBLT",XDM_CONST.IP_PROTOCOL_NETBLT, ip_proto="MFE_NSP",XDM_CONST.IP_PROTOCOL_MFE_NSP, ip_proto="MERIT_INP",XDM_CONST.IP_PROTOCOL_MERIT_INP, ip_proto="DCCP",XDM_CONST.IP_PROTOCOL_DCCP, ip_proto="3PC",XDM_CONST.IP_PROTOCOL_3PC, ip_proto="IDPR",XDM_CONST.IP_PROTOCOL_IDPR, ip_proto="XTP",XDM_CONST.IP_PROTOCOL_XTP, ip_proto="DDP",XDM_CONST.IP_PROTOCOL_DDP, ip_proto="IDPR_CMTP",XDM_CONST.IP_PROTOCOL_IDPR_CMTP, ip_proto="TP",XDM_CONST.IP_PROTOCOL_TP, ip_proto="IL",XDM_CONST.IP_PROTOCOL_IL, ip_proto="IPV6",XDM_CONST.IP_PROTOCOL_IPV6, ip_proto="SDRP",XDM_CONST.IP_PROTOCOL_SDRP, ip_proto="IPV6_ROUTE",XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, ip_proto="IPV6_FRAG",XDM_CONST.IP_PROTOCOL_IPV6_FRAG, ip_proto="IDRP",XDM_CONST.IP_PROTOCOL_IDRP, ip_proto="RSVP",XDM_CONST.IP_PROTOCOL_RSVP, ip_proto="GRE",XDM_CONST.IP_PROTOCOL_GRE, ip_proto="DSR",XDM_CONST.IP_PROTOCOL_DSR, ip_proto="BNA",XDM_CONST.IP_PROTOCOL_BNA, ip_proto="ESP",XDM_CONST.IP_PROTOCOL_ESP, ip_proto="AH",XDM_CONST.IP_PROTOCOL_AH, ip_proto="I_NLSP",XDM_CONST.IP_PROTOCOL_I_NLSP, ip_proto="SWIPE",XDM_CONST.IP_PROTOCOL_SWIPE, ip_proto="NARP",XDM_CONST.IP_PROTOCOL_NARP, ip_proto="MOBILE",XDM_CONST.IP_PROTOCOL_MOBILE, ip_proto="TLSP",XDM_CONST.IP_PROTOCOL_TLSP, ip_proto="SKIP",XDM_CONST.IP_PROTOCOL_SKIP, ip_proto="IPV6_ICMP",XDM_CONST.IP_PROTOCOL_IPV6_ICMP, ip_proto="IPV6_NONXT",XDM_CONST.IP_PROTOCOL_IPV6_NONXT, ip_proto="IPV6_OPTS",XDM_CONST.IP_PROTOCOL_IPV6_OPTS, ip_proto="CFTP",XDM_CONST.IP_PROTOCOL_CFTP, ip_proto="SAT_EXPAK",XDM_CONST.IP_PROTOCOL_SAT_EXPAK, ip_proto="KRYPTOLAN",XDM_CONST.IP_PROTOCOL_KRYPTOLAN, ip_proto="RVD",XDM_CONST.IP_PROTOCOL_RVD, ip_proto="IPPC",XDM_CONST.IP_PROTOCOL_IPPC, ip_proto="SAT_MON",XDM_CONST.IP_PROTOCOL_SAT_MON, ip_proto="VISA",XDM_CONST.IP_PROTOCOL_VISA, ip_proto="IPCV",XDM_CONST.IP_PROTOCOL_IPCV, ip_proto="CPNX",XDM_CONST.IP_PROTOCOL_CPNX, ip_proto="CPHB",XDM_CONST.IP_PROTOCOL_CPHB, ip_proto="WSN",XDM_CONST.IP_PROTOCOL_WSN, ip_proto="PVP",XDM_CONST.IP_PROTOCOL_PVP, ip_proto="BR_SAT_MON",XDM_CONST.IP_PROTOCOL_BR_SAT_MON, ip_proto="SUN_ND",XDM_CONST.IP_PROTOCOL_SUN_ND, ip_proto="WB_MON",XDM_CONST.IP_PROTOCOL_WB_MON, ip_proto="WB_EXPAK",XDM_CONST.IP_PROTOCOL_WB_EXPAK, ip_proto="ISO_IP",XDM_CONST.IP_PROTOCOL_ISO_IP, ip_proto="VMTP",XDM_CONST.IP_PROTOCOL_VMTP, ip_proto="SECURE_VMTP",XDM_CONST.IP_PROTOCOL_SECURE_VMTP, ip_proto="VINES",XDM_CONST.IP_PROTOCOL_VINES, ip_proto="TTP",XDM_CONST.IP_PROTOCOL_TTP, ip_proto="NSFNET_IGP",XDM_CONST.IP_PROTOCOL_NSFNET_IGP, ip_proto="DGP",XDM_CONST.IP_PROTOCOL_DGP, ip_proto="TCF",XDM_CONST.IP_PROTOCOL_TCF, ip_proto="EIGRP",XDM_CONST.IP_PROTOCOL_EIGRP, ip_proto="OSPFIGP",XDM_CONST.IP_PROTOCOL_OSPFIGP, ip_proto="SPRITE_RPC",XDM_CONST.IP_PROTOCOL_SPRITE_RPC, ip_proto="LARP",XDM_CONST.IP_PROTOCOL_LARP, ip_proto="MTP",XDM_CONST.IP_PROTOCOL_MTP, ip_proto="AX25",XDM_CONST.IP_PROTOCOL_AX25, ip_proto="IPIP",XDM_CONST.IP_PROTOCOL_IPIP, ip_proto="MICP",XDM_CONST.IP_PROTOCOL_MICP, ip_proto="SCC_SP",XDM_CONST.IP_PROTOCOL_SCC_SP, ip_proto="ETHERIP",XDM_CONST.IP_PROTOCOL_ETHERIP, ip_proto="ENCAP",XDM_CONST.IP_PROTOCOL_ENCAP, ip_proto="GMTP",XDM_CONST.IP_PROTOCOL_GMTP, ip_proto="IFMP",XDM_CONST.IP_PROTOCOL_IFMP, ip_proto="PNNI",XDM_CONST.IP_PROTOCOL_PNNI, ip_proto="PIM",XDM_CONST.IP_PROTOCOL_PIM, ip_proto="ARIS",XDM_CONST.IP_PROTOCOL_ARIS, ip_proto="SCPS",XDM_CONST.IP_PROTOCOL_SCPS, ip_proto="QNX",XDM_CONST.IP_PROTOCOL_QNX, ip_proto="AN",XDM_CONST.IP_PROTOCOL_AN, ip_proto="IPCOMP",XDM_CONST.IP_PROTOCOL_IPCOMP, ip_proto="SNP",XDM_CONST.IP_PROTOCOL_SNP, ip_proto="COMPAQ_PEER",XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, ip_proto="IPX_IN_IP",XDM_CONST.IP_PROTOCOL_IPX_IN_IP, ip_proto="VRRP",XDM_CONST.IP_PROTOCOL_VRRP, ip_proto="PGM",XDM_CONST.IP_PROTOCOL_PGM, ip_proto="L2TP",XDM_CONST.IP_PROTOCOL_L2TP, ip_proto="DDX",XDM_CONST.IP_PROTOCOL_DDX, ip_proto="IATP",XDM_CONST.IP_PROTOCOL_IATP, ip_proto="STP",XDM_CONST.IP_PROTOCOL_STP, ip_proto="SRP",XDM_CONST.IP_PROTOCOL_SRP, ip_proto="UTI",XDM_CONST.IP_PROTOCOL_UTI, ip_proto="SMP",XDM_CONST.IP_PROTOCOL_SMP, ip_proto="SM",XDM_CONST.IP_PROTOCOL_SM, ip_proto="PTP",XDM_CONST.IP_PROTOCOL_PTP, ip_proto="ISIS",XDM_CONST.IP_PROTOCOL_ISIS, ip_proto="FIRE",XDM_CONST.IP_PROTOCOL_FIRE, ip_proto="CRTP",XDM_CONST.IP_PROTOCOL_CRTP, ip_proto="CRUDP",XDM_CONST.IP_PROTOCOL_CRUDP, ip_proto="SSCOPMCE",XDM_CONST.IP_PROTOCOL_SSCOPMCE, ip_proto="IPLT",XDM_CONST.IP_PROTOCOL_IPLT, ip_proto="SPS",XDM_CONST.IP_PROTOCOL_SPS, ip_proto="PIPE",XDM_CONST.IP_PROTOCOL_PIPE, ip_proto="SCTP",XDM_CONST.IP_PROTOCOL_SCTP, ip_proto="FC",XDM_CONST.IP_PROTOCOL_FC, ip_proto="RSVP_E2E_IGNORE",XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, ip_proto="MOBILITY",XDM_CONST.IP_PROTOCOL_MOBILITY, ip_proto="UDPLITE",XDM_CONST.IP_PROTOCOL_UDPLITE, ip_proto="MPLS_IN_IP",XDM_CONST.IP_PROTOCOL_MPLS_IN_IP, ip_proto="MANET",XDM_CONST.IP_PROTOCOL_MANET, ip_proto="HIP",XDM_CONST.IP_PROTOCOL_HIP, ip_proto="SHIM6",XDM_CONST.IP_PROTOCOL_SHIM6, ip_proto="WESP",XDM_CONST.IP_PROTOCOL_WESP, ip_proto="ROHC",XDM_CONST.IP_PROTOCOL_ROHC, ip_proto="RESERVED",XDM_CONST.IP_PROTOCOL_RESERVED,ip_proto="0",XDM_CONST.IP_PROTOCOL_HOPOPT, ip_proto="1",XDM_CONST.IP_PROTOCOL_ICMP, ip_proto="2",XDM_CONST.IP_PROTOCOL_IGMP, ip_proto="3",XDM_CONST.IP_PROTOCOL_GGP, ip_proto="4",XDM_CONST.IP_PROTOCOL_IP, ip_proto="5",XDM_CONST.IP_PROTOCOL_ST, ip_proto="6",XDM_CONST.IP_PROTOCOL_TCP, ip_proto="7",XDM_CONST.IP_PROTOCOL_CBT, ip_proto="8",XDM_CONST.IP_PROTOCOL_EGP, ip_proto="9",XDM_CONST.IP_PROTOCOL_IGP, ip_proto="10",XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, ip_proto="11",XDM_CONST.IP_PROTOCOL_NVP_II, ip_proto="12",XDM_CONST.IP_PROTOCOL_PUP, ip_proto="13",XDM_CONST.IP_PROTOCOL_ARGUS, ip_proto="14",XDM_CONST.IP_PROTOCOL_EMCON, ip_proto="15",XDM_CONST.IP_PROTOCOL_XNET, ip_proto="16",XDM_CONST.IP_PROTOCOL_CHAOS, ip_proto="17",XDM_CONST.IP_PROTOCOL_UDP, ip_proto="18",XDM_CONST.IP_PROTOCOL_MUX, ip_proto="19",XDM_CONST.IP_PROTOCOL_DCN_MEAS, ip_proto="20",XDM_CONST.IP_PROTOCOL_HMP, ip_proto="21",XDM_CONST.IP_PROTOCOL_PRM, ip_proto="22",XDM_CONST.IP_PROTOCOL_XNS_IDP, ip_proto="23",XDM_CONST.IP_PROTOCOL_TRUNK_1, ip_proto="24",XDM_CONST.IP_PROTOCOL_TRUNK_2, ip_proto="25",XDM_CONST.IP_PROTOCOL_LEAF_1, ip_proto="26",XDM_CONST.IP_PROTOCOL_LEAF_2, ip_proto="27",XDM_CONST.IP_PROTOCOL_RDP, ip_proto="28",XDM_CONST.IP_PROTOCOL_IRTP, ip_proto="29",XDM_CONST.IP_PROTOCOL_ISO_TP4, ip_proto="30",XDM_CONST.IP_PROTOCOL_NETBLT, ip_proto="31",XDM_CONST.IP_PROTOCOL_MFE_NSP, ip_proto="32",XDM_CONST.IP_PROTOCOL_MERIT_INP, ip_proto="33",XDM_CONST.IP_PROTOCOL_DCCP, ip_proto="34",XDM_CONST.IP_PROTOCOL_3PC, ip_proto="35",XDM_CONST.IP_PROTOCOL_IDPR, ip_proto="36",XDM_CONST.IP_PROTOCOL_XTP, ip_proto="37",XDM_CONST.IP_PROTOCOL_DDP, ip_proto="38",XDM_CONST.IP_PROTOCOL_IDPR_CMTP, ip_proto="39",XDM_CONST.IP_PROTOCOL_TP, ip_proto="40",XDM_CONST.IP_PROTOCOL_IL, ip_proto="41",XDM_CONST.IP_PROTOCOL_IPV6, ip_proto="42",XDM_CONST.IP_PROTOCOL_SDRP, ip_proto="43",XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, ip_proto="44",XDM_CONST.IP_PROTOCOL_IPV6_FRAG, ip_proto="45",XDM_CONST.IP_PROTOCOL_IDRP, ip_proto="46",XDM_CONST.IP_PROTOCOL_RSVP, ip_proto="47",XDM_CONST.IP_PROTOCOL_GRE, ip_proto="48",XDM_CONST.IP_PROTOCOL_DSR, ip_proto="49",XDM_CONST.IP_PROTOCOL_BNA, ip_proto="50",XDM_CONST.IP_PROTOCOL_ESP, ip_proto="51",XDM_CONST.IP_PROTOCOL_AH, ip_proto="52",XDM_CONST.IP_PROTOCOL_I_NLSP, ip_proto="53",XDM_CONST.IP_PROTOCOL_SWIPE, ip_proto="54",XDM_CONST.IP_PROTOCOL_NARP, ip_proto="55",XDM_CONST.IP_PROTOCOL_MOBILE, ip_proto="56",XDM_CONST.IP_PROTOCOL_TLSP, ip_proto="57",XDM_CONST.IP_PROTOCOL_SKIP, ip_proto="58",XDM_CONST.IP_PROTOCOL_IPV6_ICMP, ip_proto="59",XDM_CONST.IP_PROTOCOL_IPV6_NONXT, ip_proto="60",XDM_CONST.IP_PROTOCOL_IPV6_OPTS, ip_proto="62",XDM_CONST.IP_PROTOCOL_CFTP, ip_proto="64",XDM_CONST.IP_PROTOCOL_SAT_EXPAK, ip_proto="65",XDM_CONST.IP_PROTOCOL_KRYPTOLAN, ip_proto="66",XDM_CONST.IP_PROTOCOL_RVD, ip_proto="67",XDM_CONST.IP_PROTOCOL_IPPC, ip_proto="69",XDM_CONST.IP_PROTOCOL_SAT_MON, ip_proto="70",XDM_CONST.IP_PROTOCOL_VISA, ip_proto="71",XDM_CONST.IP_PROTOCOL_IPCV, ip_proto="72",XDM_CONST.IP_PROTOCOL_CPNX, ip_proto="73",XDM_CONST.IP_PROTOCOL_CPHB, ip_proto="74",XDM_CONST.IP_PROTOCOL_WSN, ip_proto="75",XDM_CONST.IP_PROTOCOL_PVP, ip_proto="76",XDM_CONST.IP_PROTOCOL_BR_SAT_MON, ip_proto="77",XDM_CONST.IP_PROTOCOL_SUN_ND, ip_proto="78",XDM_CONST.IP_PROTOCOL_WB_MON, ip_proto="79",XDM_CONST.IP_PROTOCOL_WB_EXPAK, ip_proto="80",XDM_CONST.IP_PROTOCOL_ISO_IP, ip_proto="81",XDM_CONST.IP_PROTOCOL_VMTP, ip_proto="82",XDM_CONST.IP_PROTOCOL_SECURE_VMTP, ip_proto="83",XDM_CONST.IP_PROTOCOL_VINES, ip_proto="84",XDM_CONST.IP_PROTOCOL_TTP, ip_proto="85",XDM_CONST.IP_PROTOCOL_NSFNET_IGP, ip_proto="86",XDM_CONST.IP_PROTOCOL_DGP, ip_proto="87",XDM_CONST.IP_PROTOCOL_TCF, ip_proto="88",XDM_CONST.IP_PROTOCOL_EIGRP, ip_proto="89",XDM_CONST.IP_PROTOCOL_OSPFIGP, ip_proto="90",XDM_CONST.IP_PROTOCOL_SPRITE_RPC, ip_proto="91",XDM_CONST.IP_PROTOCOL_LARP, ip_proto="92",XDM_CONST.IP_PROTOCOL_MTP, ip_proto="93",XDM_CONST.IP_PROTOCOL_AX25, ip_proto="94",XDM_CONST.IP_PROTOCOL_IPIP, ip_proto="95",XDM_CONST.IP_PROTOCOL_MICP, ip_proto="96",XDM_CONST.IP_PROTOCOL_SCC_SP, ip_proto="97",XDM_CONST.IP_PROTOCOL_ETHERIP, ip_proto="98",XDM_CONST.IP_PROTOCOL_ENCAP, ip_proto="100",XDM_CONST.IP_PROTOCOL_GMTP, ip_proto="101",XDM_CONST.IP_PROTOCOL_IFMP, ip_proto="102",XDM_CONST.IP_PROTOCOL_PNNI, ip_proto="103",XDM_CONST.IP_PROTOCOL_PIM, ip_proto="104",XDM_CONST.IP_PROTOCOL_ARIS, ip_proto="105",XDM_CONST.IP_PROTOCOL_SCPS, ip_proto="106",XDM_CONST.IP_PROTOCOL_QNX, ip_proto="107",XDM_CONST.IP_PROTOCOL_AN, ip_proto="108",XDM_CONST.IP_PROTOCOL_IPCOMP, ip_proto="109",XDM_CONST.IP_PROTOCOL_SNP, ip_proto="110",XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, ip_proto="111",XDM_CONST.IP_PROTOCOL_IPX_IN_IP, ip_proto="112",XDM_CONST.IP_PROTOCOL_VRRP, ip_proto="113",XDM_CONST.IP_PROTOCOL_PGM, ip_proto="115",XDM_CONST.IP_PROTOCOL_L2TP, ip_proto="116",XDM_CONST.IP_PROTOCOL_DDX, ip_proto="117",XDM_CONST.IP_PROTOCOL_IATP, ip_proto="118",XDM_CONST.IP_PROTOCOL_STP, ip_proto="119",XDM_CONST.IP_PROTOCOL_SRP, ip_proto="120",XDM_CONST.IP_PROTOCOL_UTI, ip_proto="121",XDM_CONST.IP_PROTOCOL_SMP, ip_proto="122",XDM_CONST.IP_PROTOCOL_SM, ip_proto="123",XDM_CONST.IP_PROTOCOL_PTP, ip_proto="124",XDM_CONST.IP_PROTOCOL_ISIS, ip_proto="125",XDM_CONST.IP_PROTOCOL_FIRE, ip_proto="126",XDM_CONST.IP_PROTOCOL_CRTP, ip_proto="127",XDM_CONST.IP_PROTOCOL_CRUDP, ip_proto="128",XDM_CONST.IP_PROTOCOL_SSCOPMCE, ip_proto="129",XDM_CONST.IP_PROTOCOL_IPLT, ip_proto="130",XDM_CONST.IP_PROTOCOL_SPS, ip_proto="131",XDM_CONST.IP_PROTOCOL_PIPE, ip_proto="132",XDM_CONST.IP_PROTOCOL_SCTP, ip_proto="133",XDM_CONST.IP_PROTOCOL_FC, ip_proto="134",XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, ip_proto="135",XDM_CONST.IP_PROTOCOL_MOBILITY, ip_proto="136",XDM_CONST.IP_PROTOCOL_UDPLITE, ip_proto="137",XDM_CONST.IP_PROTOCOL_MPLS_IN_IP, ip_proto="138",XDM_CONST.IP_PROTOCOL_MANET, ip_proto="139",XDM_CONST.IP_PROTOCOL_HIP, ip_proto="140",XDM_CONST.IP_PROTOCOL_SHIM6, ip_proto="141",XDM_CONST.IP_PROTOCOL_WESP, ip_proto="142",XDM_CONST.IP_PROTOCOL_ROHC, ip_proto="255",XDM_CONST.IP_PROTOCOL_RESERVED,to_string(ip_proto));
[MODEL: dataset="arista_switch_raw", content_id="aristaswitch"]
/*** AAA (Authentication, Authorization, and Accounting) Events 
    (https://www.arista.com/en/um-eos/eos-user-security) ***/
call arista_switch_common_fields_modeling
| filter facility = "AAA" 
| alter 
    username = arrayindex(regextract(message, "user (\S+)"), 0),
    src =  arrayindex(regextract(message, "\[from:\s*(\S+)\]"), 0),  
    service =  arrayindex(regextract(message, "service:{0,1}\s*\'{0,1}([^\]\']+)"), 0),
    reason = arrayindex(regextract(message, "reason:\s*([^\|]+?)\]"), 0), // relevant only for mnemonic="LOGIN_FAILED" 
    auth_method = arrayindex(regextract(message, "Authentication method \'([^\']+)\'"), 0) // relevant only for mnemonic="AUTHN_FALLBACK" 
| alter 
    src_ipv4 = if(src ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", src, null),
    src_ipv6 = if(src ~= "\w{1,3}\:", src, null),
    src_hostname = if(src !~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" and src !~= "\w{1,3}\:", src, null)
| alter 
    xdm.source.ipv4 = src_ipv4,
    xdm.source.ipv6 = src_ipv6,
    xdm.source.host.hostname = src_hostname,
    xdm.source.process.name = service, 
    xdm.source.user.username = username,
    xdm.event.outcome = if(mnemonic IN ("LOGIN", "LOGOUT"), XDM_CONST.OUTCOME_SUCCESS, mnemonic="AUTHN_FALLBACK", XDM_CONST.OUTCOME_PARTIAL, mnemonic="LOGIN_FAILED", XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN),
    xdm.event.outcome_reason = reason, // relevant only for mnemonic="LOGIN_FAILED" 
    xdm.auth.auth_method = auth_method, // relevant only for mnemonic="AUTHN_FALLBACK" 
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION); 
    

/*** Accounting Events 
    (https://www.arista.com/en/um-eos/eos-user-security) ***/  
call arista_switch_common_fields_modeling
| filter facility = "ACCOUNTING" 
| alter 
    message_header = split(arrayindex(regextract(message, "\S+\s+\S+\s+\S+\s+\S+\s+\S+"), 0)),
    task_id = arrayindex(regextract(message, "task_id=(\d+)"), 0),
    elapsed_time = arrayindex(regextract(message, "elapsed_time=(\S+)"), 0),
    service = arrayindex(regextract(message, "service=(\S+)"), 0),
    privilege_level = arrayindex(regextract(message, "priv\-lvl=(\d+)"), 0),
    cmd = arrayindex(regextract(message, "cmd=(.+)[\w+=]*"), 0)
| alter 
    dvc = arrayindex(message_header, 0), // the target switch hostname 
    username = arrayindex(message_header, 1), // user who logged in to the switch 
    login_process = arrayindex(message_header, 2), // eg. ssh 
    src =  arrayindex(message_header, 3), // the source remote host that initiated the login 
    process_phase =  arrayindex(message_header, 4) // indicates whether the process started (start) or completed (stop)
| alter 
    src_ipv4 = if(src ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", src, null),
    src_ipv6 = if(src ~= "\w{1,3}\:", src, null),
    src_hostname = if(src !~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" and src !~= "\w{1,3}\:", src, null),
    dst_ipv4 = if(dvc ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dvc, null),
    dst_ipv6 = if(dvc ~= "\w{1,3}\:", dvc, null),
    dst_hostname = if(dvc !~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" and dvc !~= "\w{1,3}\:", dvc, null)
| alter 
    xdm.source.ipv4 = src_ipv4,
    xdm.source.ipv6 = src_ipv6,
    xdm.source.host.hostname = src_hostname,
    xdm.source.user.username = username, 
    xdm.source.process.name = login_process,
    xdm.target.ipv4 = dst_ipv4,
    xdm.target.ipv6 = dst_ipv6,
    xdm.target.host.hostname = dst_hostname,
    xdm.target.process.name = service, 
    xdm.target.process.identifier = task_id, 
    xdm.target.process.command_line = cmd,
    xdm.event.duration = to_number(elapsed_time),
    xdm.event.is_completed = if(process_phase = "stop", true, false),
    xdm.auth.privilege_level = if(privilege_level in ("0", "1"), XDM_CONST.PRIVILEGE_LEVEL_USER , privilege_level = "15", XDM_CONST.PRIVILEGE_LEVEL_ADMIN , privilege_level),
    xdm.auth.auth_method = login_process;


/*** ACL (Access List) Events 
    (https://www.arista.com/en/um-eos/eos-acls-and-route-maps) ***/  
call arista_switch_common_fields_modeling
| filter facility = "ACL"
| alter
    acl_tuple = split(arrayindex(regextract(message, "list\s+(\S+\s+\S+\s+\S+\s+\S+\s+\S+)"), 0)),
    src_ip = if(mnemonic = "IPACCESS", arrayindex(regextract(message, "([\d\.\:]+)\(*\d{0,5}\)*\s*\-\>\s*\S+"), 0), null),
    dst_ip = if(mnemonic = "IPACCESS", arrayindex(regextract(message, "\S+\s*\-\>\s*([\d\.\:]+)"), 0), null),
    src_port = if(mnemonic = "IPACCESS", arrayindex(regextract(message, "\((\d{1,5})\)\s*\-\>"), 0), null),
    dst_port = if(mnemonic = "IPACCESS", arrayindex(regextract(message, "\-\>\s*[\d\.\:]+\((\d{1,5})\)"), 0), null),
    icmp_type = if(mnemonic = "IPACCESS", to_integer(arrayindex(regextract(message, "type=(\d+)"), 0)), null),
    icmp_code = if(mnemonic = "IPACCESS", to_integer(arrayindex(regextract(message, "code=(\d+)"), 0)), null),
    smac1 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "(\S{12,17})\s*\-\>\s*\S+$"), 0), null), // smac -> dmac 
    smac2 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "([a-fA-F\d\:\-]{12,17})\s+\S+\s*\:\s*\d{1,5}\s*\-\>\s*\S+\s+\S+"), 0), null), // smac sip : spt -> dmac dip : dpt
    smac3 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "([a-fA-F\d\:\-]{12,17})\s+\S+\s*\-\>"), 0), null), // smac sip -> dmac dip
    dmac1 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\S+\s*\-\>\s*(\S{12,17})$"), 0), null), // smac -> dmac
    dmac2 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\-\>\s*([a-fA-F\d\:\-]{12,17})\s+\S+\s*\:\s*\d{1,5}$"), 0), null), // smac sip : spt -> dmac dip : dpt
    dmac3 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\-\>\s*([a-fA-F\d\:\-]{12,17})\s+\S+$"), 0), null), // smac sip -> dmac dip
    sip1 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "[a-fA-F\d\:\-]{12,17}\s+(\S+)\s*\:\s*\d{1,5}\s*\-\>\s*\S+\s+\S+"), 0), null), // smac sip : spt -> dmac dip : dpt
    sip2 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "[a-fA-F\d\:\-]{12,17}\s+(\S+)\s*\-\>"), 0), null), // smac sip -> dmac dip
    dip1 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\-\>\s*[a-fA-F\d\:\-]{12,17}\s+(\S+)\s*\:\s*\d{1,5}$"), 0), null), // smac sip : spt -> dmac dip : dpt
    dip2 = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\-\>\s*[a-fA-F\d\:\-]{12,17}\s+(\S+)$"), 0), null), // smac sip -> dmac dip
    spt = if(mnemonic="MACACCESS", arrayindex(regextract(message, "[a-fA-F\d\:\-]{12,17}\s+\S+\s*\:\s*(\d{1,5})\s*\-\>\s*\S+\s+\S+"), 0), null), // smac sip : spt -> dmac dip : dpt
    dpt = if(mnemonic="MACACCESS", arrayindex(regextract(message, "\-\>\s*[a-fA-F\d\:\-]{12,17}\s+\S+\s*\:\s*(\d{1,5})$"), 0), null), // smac sip : spt -> dmac dip : dpt
    proto = if(mnemonic="MACACCESS", uppercase(arrayindex(regextract(message, "([a-zA-Z]+)\s+[a-fA-F\d\:\-]{12,17}\s+[\d\.\:a-fA-F]+\s*\:\s*\d{1,5}\s*\-\>"), 0)), null)
| alter 
    acl_name = arrayindex(acl_tuple, 0),
    switch_interface = arrayindex(acl_tuple, 1),
    acl_filter_action = arrayindex(acl_tuple, 2),
    ip_proto = if(mnemonic = "IPACCESS", uppercase(arrayindex(acl_tuple, 3)), null), 
    vlan_num = if(mnemonic = "MACACCESS", to_integer(arrayindex(acl_tuple, 3)), null),
    src_ip = coalesce(src_ip, sip1, sip2),
    dst_ip = coalesce(dst_ip, dip1, dip2),
    src_mac = coalesce(smac1, smac2, smac3),
    dst_mac = coalesce(dmac1, dmac2, dmac3),
    src_port = to_integer(coalesce(src_port, spt)),
    dst_port = to_integer(coalesce(dst_port, dpt))
| alter 
    src_ipv4 = if(src_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", src_ip, null),
    src_ipv6 = if(src_ip ~= "\w{1,3}\:", src_ip, null),
    dst_ipv4 = if(dst_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dst_ip, null),
    dst_ipv6 = if(dst_ip ~= "\w{1,3}\:", dst_ip, null),
    ip_proto = coalesce(ip_proto, proto)
| call arista_switch_map_ip_protocol
| alter 
    xdm.source.ipv4 = src_ipv4,
    xdm.source.ipv6 = src_ipv6,
    xdm.source.port = src_port, 
    xdm.source.host.mac_addresses = arraycreate(src_mac),
    xdm.target.ipv4 = dst_ipv4,
    xdm.target.ipv6 = dst_ipv6,
    xdm.target.port = dst_port, 
    xdm.target.host.mac_addresses = arraycreate(dst_mac),
    xdm.target.interface = switch_interface,
    xdm.target.vlan = vlan_num,
    xdm.observer.action = acl_filter_action,
    xdm.event.outcome = if(acl_filter_action = "permitted", XDM_CONST.OUTCOME_SUCCESS, acl_filter_action="denied", XDM_CONST.OUTCOME_FAILED, acl_filter_action),
    xdm.event.outcome_reason = acl_name, 
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.network.rule = acl_name, 
    xdm.network.icmp.type = icmp_type,
    xdm.network.icmp.code = icmp_code;


/*** BFD (Bidirectional Forwarding Detection) Events 
    (https://www.arista.com/en/um-eos/eos-bidirectional-forwarding-detection) ***/  
call arista_switch_common_fields_modeling
| filter facility = "BFD" 
| alter 
    peer_ip =  arrayindex(regextract(message, "ip:\s*([^,]+)"), 0),  
    interface =  arrayindex(regextract(message, "intf:\s*([^,]+)"), 0),  
    state = uppercase(arrayindex(regextract(message, "changed state from \S+ to (\S+)"), 0)),
    old_state = uppercase(arrayindex(regextract(message, "changed state from (\S+) to \S+"), 0)),
    reason = arrayindex(regextract(message, "diag (\S+)"), 0) // diagnostic code specifying the local system reason for the last change to Down state
| alter 
    peer_ipv4 = if(peer_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", peer_ip, null),
    peer_ipv6 = if(peer_ip ~= "\w{1,3}\:", peer_ip, null)
| alter 
    xdm.target.ipv4 = peer_ipv4,
    xdm.target.ipv6 = peer_ipv6,
    xdm.target.interface = interface,
    xdm.target.resource.value = state,
    xdm.target.resource.type = if(state != null and state != "", "state", null),
    xdm.target.resource_before.value = old_state,
    xdm.target.resource_before.type = if(old_state != null and old_state != "", "state", null),
    xdm.observer.action = state,
    xdm.event.outcome = if(state = "UP", XDM_CONST.OUTCOME_SUCCESS, state="DOWN", XDM_CONST.OUTCOME_FAILED, state != null, XDM_CONST.OUTCOME_UNKNOWN, null),
    xdm.event.outcome_reason = reason, 
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** BGP (Border Gateway Protocol) RIB (Routing Information Base) Events 
    (https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp) ***/  
call arista_switch_common_fields_modeling
| filter facility contains "BGP" 
| alter 
    peer_ip = arrayindex(regextract(message, "peer\s*([a-fA-F\d\:\.]+)"), 0),  
    rib_src_peer_ip = arrayindex(regextract(message, "peer\s*([a-fA-F\d\:\.]+)\+\d{1,5}"), 0),
    rib_src_peer_port = to_integer(arrayindex(regextract(message, "peer\s*[a-fA-F\d\:\.]+\+(\d{1,5})"), 0)),   
    neighbor_ip = arrayindex(regextract(message, "neighbor\s*(\S+)"), 0),  
    asn =  to_integer(arrayindex(regextract(message, "AS (\d+)"), 0)), 
    old_state1 = arrayindex(regextract(message, "old state (\S+)"), 0), // Rib: %BGP-5-ADJCHANGE:
    old_state2 = arrayindex(regextract(message, "\(AS \d+\) (\S+) to \S+"), 0),  //  Rib: %BGP-BFD-STATE-CHANGE:
    new_state1 = arrayindex(regextract(message, "new state (\S+)"), 0), // Rib: %BGP-5-ADJCHANGE: 
    new_state2 = arrayindex(regextract(message, "\(AS \d+\) \S+ to (\S+)"), 0), // Rib: %BGP-BFD-STATE-CHANGE:
    trigger_event = arrayindex(regextract(message, "old state \S+ event (\S+) new state \S+"), 0),
    bytes = to_integer(arrayindex(regextract(message, "sent to neighbor .+? (\d+) bytes"), 0))
| alter 
    peer_ip = coalesce(peer_ip, rib_src_peer_ip, neighbor_ip),
    old_state = uppercase(coalesce(old_state1, old_state2)),
    new_state = uppercase(coalesce(new_state1, new_state2))
| alter 
    peer_ipv4 = if(peer_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", peer_ip, null),
    peer_ipv6 = if(peer_ip ~= "\w{1,3}\:", peer_ip, null)
| alter 
    xdm.source.sent_bytes = bytes,
    xdm.source.ipv4 = if(rib_src_peer_ip != null, peer_ipv4, null),
    xdm.source.ipv6 = if(rib_src_peer_ip != null, peer_ipv6, null),
    xdm.source.port = if(rib_src_peer_port != null, rib_src_peer_port, null),
    xdm.target.ipv4 = peer_ipv4,
    xdm.target.ipv6 = peer_ipv6,
    xdm.target.asn.as_number = asn,
    xdm.target.resource.type = if(new_state != null and new_state != "", "state", null),
    xdm.target.resource.value = new_state,
    xdm.target.resource_before.type = if(old_state != null and old_state != "", "state", null),
    xdm.target.resource_before.value = old_state,
    xdm.observer.action = new_state,
    xdm.event.is_completed = if(new_state = "ESTABLISHED", true, new_state != null, false, null),
    xdm.event.outcome = if(new_state in("UP", "ESTABLISHED"), XDM_CONST.OUTCOME_SUCCESS, new_state in("DOWN", "ACTIVE"), XDM_CONST.OUTCOME_FAILED, new_state in("IDLE", "CONNECT", "OPENSENT", "OPENCONFIRM"), XDM_CONST.OUTCOME_PARTIAL, XDM_CONST.OUTCOME_UNKNOWN),
    xdm.event.outcome_reason = trigger_event, 
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** ETH Events 
    (https://www.arista.com/en/um-eos/eos-ethernet-ports) ***/  
call arista_switch_common_fields_modeling
| filter facility = "ETH" 
| alter 
    host_mac_address =  arrayindex(regextract(message, "Host ([a-fA-F\d\:\-]{12,17})"), 0),  
    src_interface =  arrayindex(regextract(message, "between interface (\S+)"), 0),  
    dst_interface =  arrayindex(regextract(message, "between interface \S+ and interface (\S+)"), 0),  
    vlan = to_integer(arrayindex(regextract(message, "in VLAN (\d+)"), 0))
| alter 
    xdm.source.vlan = vlan,
    xdm.source.interface = src_interface,
    xdm.source.host.mac_addresses = arraycreate(host_mac_address),
    xdm.target.vlan = vlan, 
    xdm.target.interface = dst_interface,
    xdm.target.host.mac_addresses = arraycreate(host_mac_address),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** EBRA (Ethernet Bridging Agent) Line Protocol Events ***/
call arista_switch_common_fields_modeling
| filter facility="LINEPROTO"
| alter 
    interface =  arrayindex(regextract(message, "on Interface ([\w\/]+)"), 0),
    state =  arrayindex(regextract(message, "changed state to (\S+)"), 0)
| alter 
    ipv4 = if(dvc ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dvc, null),
    ipv6 = if(dvc ~= "\w{1,3}\:", dvc, null)
| alter 
    xdm.source.ipv4 = ipv4,
    xdm.source.ipv6 = ipv6,
    xdm.source.interface = interface,
    xdm.source.host.hostname = if(ipv4 = null and ipv6 = null, dvc, null),
    xdm.target.ipv4 = ipv4,
    xdm.target.ipv6 = ipv6,
    xdm.target.interface = interface,
    xdm.target.host.hostname = if(ipv4 = null and ipv6 = null, dvc, null),
    xdm.event.outcome = state,
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** FLOW CONTROL Events 
    (https://www.arista.com/en/um-eos/eos-ethernet-ports) ***/  
call arista_switch_common_fields_modeling
| filter facility="FLOWCONTROL"
| alter 
    interface =  arrayindex(regextract(message, "on Interface ([\w\/]+)"), 0),
    ipv4 = if(dvc ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dvc, null),
    ipv6 = if(dvc ~= "\w{1,3}\:", dvc, null)
| alter 
    xdm.source.ipv4 = ipv4,
    xdm.source.ipv6 = ipv6,
    xdm.source.interface = interface,
    xdm.source.host.hostname = if(ipv4 = null and ipv6 = null, dvc, null),
    xdm.target.ipv4 = ipv4,
    xdm.target.ipv6 = ipv6,
    xdm.target.interface = interface,
    xdm.target.host.hostname = if(ipv4 = null and ipv6 = null, dvc, null),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** IGMP (Internet Group Management Protocol) Events 
    (https://www.arista.com/en/um-eos/eos-igmp-and-igmp-snooping) ***/  
call arista_switch_common_fields_modeling
| filter facility contains "IGMP"
| alter 
    vlan = to_integer(arrayindex(regextract(message, "VLAN (\d+)"), 0)), 
    src_ip =  arrayindex(regextract(message, "received from (\S+) on"), 0),  
    dst_ip =  arrayindex(regextract(message, "received from \S+ on \S+ for ([a-fA-F\d\.\:]+)"), 0),  
    interface =  arrayindex(regextract(message, "received from \S+ on ([\w\-\/]+)"), 0) 
| alter 
    src_ipv4 = if(src_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", src_ip, null),
    src_ipv6 = if(src_ip ~= "\w{1,3}\:", src_ip, null),
    dst_ipv4 = if(dst_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dst_ip, null),
    dst_ipv6 = if(dst_ip ~= "\w{1,3}\:", dst_ip, null),
    ip_proto = "IGMP"
| call arista_switch_map_ip_protocol
| alter 
    xdm.source.ipv4 = src_ipv4,
    xdm.source.ipv6 = src_ipv6,
    xdm.target.ipv4 = dst_ipv4,
    xdm.target.ipv6 = dst_ipv6,
    xdm.target.interface = interface,
    xdm.target.vlan = vlan,
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** LAG (Link Aggregation Group) Events 
    (https://arista.my.site.com/AristaCommunity/s/article/how-to-configure-link-aggregation-groups-in-eos) ***/  
call arista_switch_common_fields_modeling
| filter facility = "LAG" 
| alter 
    interface =  arrayindex(regextract(message, "^Interface ([\w\/]+)"), 0),  
    remote_switch_name = arrayindex(regextract(message, "\((\w+)\)\s*[a-fA-F\d\.\:]+\--"), 0),
    remote_switch_ip = arrayindex(regextract(message, "\(\w+\)\s*([a-fA-F\d\.\:]+)\--"), 0),
    remote_switch_interface = arrayindex(regextract(message, "\(\w+\)\s*[a-fA-F\d\.\:]+\--\s*([^\*]+)"), 0),
    reason =  arrayindex(regextract(message, "due to:\s*(.+)"), 0)
| alter 
    dst_ipv4 = if(remote_switch_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", remote_switch_ip, null),
    dst_ipv6 = if(remote_switch_ip ~= "\w{1,3}\:", remote_switch_ip, null)
| alter 
    xdm.source.interface = interface,
    xdm.target.ipv4 = dst_ipv4,
    xdm.target.ipv6 = dst_ipv6,
    xdm.target.host.hostname = remote_switch_name,
    xdm.target.interface = remote_switch_interface,
    xdm.event.outcome = mnemonic, 
    xdm.event.outcome_reason = reason,
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** LLDP (Link Layer Discovery Protocol) Events 
    (https://www.arista.com/en/um-eos/eos-link-layer-discovery-protocol) ***/  
call arista_switch_common_fields_modeling
| filter facility = "LLDP" 
| alter 
    interface =  arrayindex(regextract(message, "on interface ([\w\/]+)"), 0),  
    remote_chassis_id = arrayindex(regextract(message, "neighbor with chassisId (\S+)"), 0),
    remote_interface = arrayindex(regextract(message,  "neighbor with chassisId \S+ and portId \"*([\w\/]+)\"*"), 0)
| alter 
    xdm.source.interface = interface,
    xdm.target.interface = remote_interface,
    xdm.target.host.device_id = remote_chassis_id,
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** PROCMGR (Process Manager) Events ***/  
call arista_switch_common_fields_modeling
| filter facility = "PROCMGR" 
| alter 
    process1 =  arrayindex(regextract(message, "^\'(\S+)\'"), 0),  
    process2 =  arrayindex(regextract(message, "from \'(\S+)\'"), 0),  
    process3 =  arrayindex(regextract(message, "Restarting \'(\S+)\'"), 0),  
    process4 =  arrayindex(regextract(message, "\'(\S+)\' starting"), 0),  
    process5 =  arrayindex(regextract(message, "\'(\S+)\' \(PID"), 0),  
    pid = to_integer(arrayindex(regextract(message, "[\s\(]PID=(\d+)"), 0)),
    ppid = arrayindex(regextract(message, "PPID=(\d+)"), 0),
    exe_path = arrayindex(regextract(message, "execing \'([^\']+)"), 0)
| alter 
    process_name = coalesce(process1, process2, process3, process4, process5)
| alter 
    xdm.source.process.name = process_name,
    xdm.source.process.pid = pid,
    xdm.source.process.parent_id = ppid,
    xdm.source.process.executable.path = exe_path;


/*** SECURITY Events 
    (https://www.arista.com/en/um-eos/eos-security) ***/  
call arista_switch_common_fields_modeling
| filter facility = "SECURITY" 
| alter 
    user =  arrayindex(regextract(message, "Session for user (\S+) on"), 0),  
    session_service =  arrayindex(regextract(message, "Session for user \S+ on service (\S+)"), 0),
    outcome =  arrayindex(regextract(message, "(\w+) due to"), 0),  
    reason =  arrayindex(regextract(message, "due to ([^\.]+)"), 0)
| alter 
    xdm.source.user.username  = user,
    xdm.source.process.name = session_service,
    xdm.event.outcome = outcome, 
    xdm.event.outcome_reason = reason,
    xdm.auth.auth_method = session_service;


/*** STP (Spanning Tree Protocol) Events 
    (https://www.arista.com/en/um-eos/eos-spanning-tree-protocol) ***/  
call arista_switch_common_fields_modeling
| filter facility = "SPANTREE" 
| alter 
    interface = arrayindex(regextract(message, "^Interface ([\w\/]+)"), 0),  
    vlan = to_integer(arrayindex(regextract(message, "instance V[Ll](\d+)"), 0)),
    action = arrayindex(regextract(message, "has been (\w+ \S+ instance)"), 0),
    state = arrayindex(regextract(message, "state is now (.+)"), 0)
| alter 
    xdm.source.interface = interface,
    xdm.target.vlan = vlan,
    xdm.event.operation = action, 
    xdm.event.outcome = if(state = "not stable", XDM_CONST.OUTCOME_FAILED, state = "stable", XDM_CONST.OUTCOME_SUCCESS, null),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK);


/*** SYS (System) Configuration Agent Events ***/  
call arista_switch_common_fields_modeling
| filter facility = "SYS"
| alter 
    user = arrayindex(regextract(message, "from \S+ by (\S+)"), 0),  
    target_ip = arrayindex(regextract(message, "from \S+ by \S+ on \S+\s*\(([^\)]+)"), 0),
    interface = if(process = "ConfigAgent", arrayindex(regextract(message, "^\w+\(([^\)]+)"), 0), null)
| alter 
    dst_ipv4 = if(target_ip ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target_ip, null),
    dst_ipv6 = if(target_ip ~= "\w{1,3}\:", target_ip, null)
| alter 
    xdm.source.interface = interface,
    xdm.source.user.username = user,
    xdm.target.ipv4 = dst_ipv4,
    xdm.target.ipv6 = dst_ipv6;


/*** Fallback for All Other Arista Switch Event Types. 
    This filter is defined for handling all other Arista event types 
    that do not have an explicit dedicated filter, hence only generic mapping is applied. ***/  
call arista_switch_common_fields_modeling
| filter 
    facility not in ("AAA", "ACCOUNTING", "ACL", "BFD", "BGP", "ETH", "FLOWCONTROL", "IGMP", "LAG", "LINEPROTO", "LLDP", "PROCMGR", "SECURITY", "SPANTREE", "SYS") 
    and facility !~= "IGMP|BGP"
| alter 
    user = arrayindex(regextract(message, "for user (\S+)"), 0),  
    uid = arrayindex(regextract(message, "uid=(\d+)"), 0),
    process_name = arrayindex(regextract(message, "process \'([^\']+)"), 0),
    role = arrayindex(regextract(message, "role \'([^\']+)"), 0)
| alter
    roles = arraycreate(role)
| alter 
    xdm.source.process.name = process_name,
    xdm.source.user.groups = roles,
    xdm.source.user.username = user,
    xdm.source.user.identifier = uid; 

/*** End of Arista EOS Switch Modeling Rules ***/


[RULE: generic_devops_rule content_id="azuredevops"]
alter
    get_data = _raw_log ->[0].data{}
| alter
    get_data_IpAddress = get_data -> IpAddress,
    get_data_ActorCUID = get_data -> ActorCUID,
    get_data_ProjectId = get_data -> ProjectId
| alter
    IpAddressv4 = if(get_data_IpAddress != null, arrayindex(regextract(get_data_IpAddress, "((?:\d{1,3}\.){3}\d{1,3})"), 0), arrayindex(regextract(IpAddress, "((?:\d{1,3}\.){3}\d{1,3})"), 0)),
    IpAddressv6 = if(get_data_IpAddress != null, arrayindex(regextract(get_data_IpAddress, "((?:[a-fA-F\d]{0,4}\:){2,7}[a-fA-F\d]{0,4})"), 0), arrayindex(regextract(IpAddress, "((?:[a-fA-F\d]{0,4}\:){2,7}[a-fA-F\d]{0,4})"), 0)),
    IsUser = if(ActorCUID = "00000000-0000-0000-0000-000000000000" OR get_data_ActorCUID ="00000000-0000-0000-0000-000000000000", to_boolean("False"), to_boolean("True"))
| alter
    xdm.source.user.upn = coalesce(ActorUPN, get_data -> ActorUPN),
    xdm.source.user.identifier = if(IsUser = False, null, get_data_ActorCUID != null, get_data_ActorCUID, ActorCUID),
    xdm.source.user.identity_type = if(IsUser = True, XDM_CONST.IDENTITY_TYPE_USER, XDM_CONST.IDENTITY_TYPE_MACHINE),
    xdm.auth.auth_method = coalesce(AuthenticationMechanism, get_data -> AuthenticationMechanism),
    xdm.session_context_id = coalesce(CorrelationId, get_data -> CorrelationId),
    xdm.event.description = coalesce(Details, get_data -> Details),
    xdm.source.user.scope = XDM_CONST.SCOPE_TYPE_AZURE,
    xdm.event.operation_sub_type = coalesce(Category, get_data -> CategoryDisplayName),
    xdm.source.cloud.project_id = if(ProjectId = "00000000-0000-0000-0000-000000000000" OR get_data_ProjectId = "00000000-0000-0000-0000-000000000000", null, get_data_ProjectId != null, get_data_ProjectId, ProjectId),
    xdm.source.cloud.project = coalesce(ProjectName, get_data -> ProjectName),
    xdm.source.user_agent = coalesce(UserAgent, get_data -> UserAgent),
    xdm.source.ipv4 = IpAddressv4,
    xdm.source.ipv6 = IpAddressv6,
    xdm.event.type = coalesce(OperationName, get_data -> OperationName, get_data -> ActionId),
    xdm.event.id = coalesce(Id, get_data -> Id),
    xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AZURE,
    xdm.event.original_event_type = coalesce(Type, get_data -> eventType),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_SAAS);
[MODEL: dataset = msft_azure_devops_raw, content_id="azuredevops"]
// Licensing events
filter Area = "Licensing" OR _raw_log ->[0].data.Area = "Licensing"
| call generic_devops_rule
| alter
    get_data_Details = get_data -> Details,
    get_data_Data = get_data -> Data
| alter
    DetailsUsernameOrGroupName = if(get_data != null, arrayindex(regextract(get_data_Details, "\"(.+)\""),0), arrayindex(regextract(Details,"\"(.+)\""),0))
| alter
    xdm.target.user.identifier = coalesce(Data -> UserIdentifier, get_data_Data -> UserIdentifier),
    xdm.target.user.username = if(Data -> UserIdentifier != null OR get_data_Data -> UserIdentifier != null, DetailsUsernameOrGroupName),
    xdm.target.user.groups = if(Data -> GroupIdentifier != null OR get_data_Data -> GroupIdentifier != null, arraycreate(DetailsUsernameOrGroupName)),
    xdm.event.outcome_reason = coalesce(Data -> Reason, get_data_Data -> Reason),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Extension events
filter Area = "Extension" OR _raw_log ->[0].data.Area = "Extension"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    xdm.target.application.publisher = coalesce(Data -> PublisherName, get_data_Data -> PublisherName),
    xdm.target.application.name = coalesce(Data -> ExtensionName, get_data_Data -> ExtensionName),
    xdm.target.application.version = coalesce(Data -> Version, get_data_Data -> Version),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Git events
filter Area = "Git" OR _raw_log ->[0].data.Area = "Git"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter //xdm mapping
    xdm.target.resource.type = "Git Repository",
    xdm.target.resource.id = coalesce(Data -> RepoId, get_data_Data -> RepoId),
    xdm.target.resource.name = coalesce(Data -> RepoName, get_data_Data -> RepoName),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Group events
filter Area = "Group" OR _raw_log ->[0].data.Area = "Group"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    xdm.source.process.name = coalesce(Data -> CallerProcedure, get_data_Data -> CallerProcedure),
    xdm.target.user.groups = if(get_data != null, arraycreate(concat("Id: ", get_data_Data -> GroupId), concat("Name: ", get_data_Data -> GroupName)), arraycreate(concat("Id: ",Data -> GroupId), concat("Name: ", Data -> GroupName))),
    xdm.target.user.identifier = coalesce(Data -> MemberId, get_data_Data -> MemberId),
    xdm.target.user.username = coalesce(Data -> MemberDisplayName, get_data_Data -> MemberDisplayName),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Library events
filter Area = "Library" OR _raw_log ->[0].data.Area = "Library"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    AgentPoolId = coalesce(Data -> AgentPoolId, get_data_Data -> AgentPoolId),
    AgentPoolName = coalesce(Data -> AgentPoolName, get_data_Data -> AgentPoolName),
    ConnectionId = coalesce(Data -> ConnectionId, get_data_Data -> ConnectionId),
    ConnectionName = coalesce(Data -> ConnectionName, get_data_Data -> ConnectionName),
    VariableGroupId = coalesce(Data -> VariableGroupId, get_data_Data -> VariableGroupId),
    VariableGroupName = coalesce(Data -> VariableGroupName, get_data_Data -> VariableGroupName)
| alter
    ResourceType = if(AgentPoolId != null, to_string("Agent Pool"), ConnectionId != null, to_string("Service Connection"), VariableGroupId != null, to_string("Variable Group"))
| alter
    xdm.target.agent.identifier = coalesce(Data -> AgentName, get_data_Data -> AgentName),
    xdm.network.session_id = ConnectionId,
    xdm.target.resource.id = coalesce(AgentPoolId, ConnectionId, VariableGroupId),
    xdm.target.resource.name = coalesce(AgentPoolName, ConnectionName, VariableGroupName),
    xdm.target.resource.type = ResourceType,
    xdm.target.resource.sub_type = coalesce(Data -> ConnectionType, get_data_Data -> ConnectionType, Data -> VariableGroupType, get_data_Data -> VariableGroupType, Data -> Type, get_data_Data -> Type),
    xdm.source.process.name = coalesce(Data -> CallerProcedure, get_data_Data -> CallerProcedure),
    xdm.target.agent.type = if(Data -> AgentId != null OR get_data_Data -> AgentId != null, XDM_CONST.AGENT_TYPE_CLOUD),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Token events
filter Area = "Token" OR _raw_log ->[0].data.Area = "Token"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    OwnerName = if(get_data_Data -> OwnerName != null, arrayindex(regextract(get_data_Data -> OwnerName, "user\s\"(.+)\""),0), Data -> OwnerName != null ,arrayindex(regextract(Data -> OwnerName, "user\s\"(.+)\""),0)),
    TokenType = if(OperationName CONTAINS "Ssh", "SSH Key", get_data -> OperationName CONTAINS "Ssh", "SSH Key", "Personal Access Token")
| alter //xdm mapping
    xdm.target.resource.type = TokenType,
    xdm.target.resource.sub_type = coalesce(Data -> TokenType, get_data_Data -> TokenType),
    xdm.target.resource.name = coalesce(Data -> DisplayName, get_data_Data -> DisplayName),
    xdm.target.user.identifier = coalesce(Data -> TargetUser, get_data_Data -> TargetUser),
     xdm.target.user.username = OwnerName,
     xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Policy events
filter Area = "Policy" OR _raw_log ->[0].data.Area = "Policy"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter //xdm mapping
    xdm.target.resource.id = coalesce(Data -> PolicyTypeId, get_data_Data -> PolicyTypeId),
    xdm.target.resource.name = coalesce(Data -> PolicyTypeDisplayName, get_data_Data -> PolicyTypeDisplayName),
    xdm.target.resource.type = to_string("Policy"),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Project events
filter Area = "Project" OR _raw_log ->[0].data.Area = "Project"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data,
    ResourceType = if(OperationName IN ("*Area*"), to_string("Area Path"), get_data -> OperationName IN ("*Area*"), to_string("Area Path"), OperationName IN ("*IterationPath*"), to_string("Iteration Path"), get_data -> OperationName IN ("*IterationPath*"), to_string("Iteration Path"))
| alter //xdm mapping
    xdm.target.process.name = coalesce(Data -> ProcessName, get_data_Data -> processName),
    xdm.target.resource.name = coalesce(Data -> Path, get_data_Data -> Path),
    xdm.target.resource.type = ResourceType,
    xdm.event.outcome = if(OperationName IN ("*Failed"),XDM_CONST.OUTCOME_FAILED, get_data -> OperationName IN ("*Failed"), XDM_CONST.OUTCOME_FAILED, OperationName IN("*Queued"), XDM_CONST.OUTCOME_PARTIAL, get_data -> OperationName IN("*Queued"), XDM_CONST.OUTCOME_PARTIAL, OperationName IN ("*Completed","Project.AreaPath.Create", "Project.AreaPath.Delete", "Project.AreaPath.Update", "Project.IterationPath.Create", "Project.IterationPath.Update", "Project.IterationPath.Delete", "Project.Process.Modify", "Project.Process.ModifyWithoutOldProcess") ,XDM_CONST.OUTCOME_SUCCESS, get_data -> OperationName IN ("*Completed","Project.AreaPath.Create", "Project.AreaPath.Delete", "Project.AreaPath.Update", "Project.IterationPath.Create", "Project.IterationPath.Update", "Project.IterationPath.Delete", "Project.Process.Modify", "Project.Process.ModifyWithoutOldProcess") ,XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_UNKNOWN);

//Release events
filter Area = "Release" OR _raw_log ->[0].data.Area = "Release"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    ResourceType = if(OperationName IN ("*Pipeline*"), to_string("Release Pipeline"), get_data -> OperationName IN ("*Pipeline*"), to_string("Release Pipeline"), to_string("Release")),
    ReleaseId = coalesce(Data -> ReleaseId, get_data_Data -> ReleaseId)
| alter //xdm mapping
    xdm.source.process.name = coalesce(Data -> CallerProcedure, get_data_Data -> CallerProcedure),
    xdm.target.resource.id = if(ResourceType = "Release Pipeline" AND get_data = null, Data -> PipelineId, ResourceType = "Release Pipeline", get_data_Data -> PipeLineId, ReleaseId != null, ReleaseId, get_data_Data = null, Data -> ReleaseEnvironmentSteps[0].ReleaseId, get_data_Data -> ReleaseEnvironmentSteps[0].ReleaseId),
    xdm.target.resource.name = if(ResourceType = "Release Pipeline" AND get_data = null, Data -> PipeLineName, ResourceType = "Release Pipeline", get_data_Data -> PipeLineName, get_data_Data = null, Data -> ReleaseName, get_data_Data -> ReleaseName),
    xdm.target.resource.type = ResourceType,
    xdm.event.outcome_reason = coalesce(Data -> ApprovalType, get_data_Data -> ApprovalType, Data -> Reason, get_data_Data -> Reason),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Security events
filter Area = "Permissions" OR _raw_log ->[0].data.Area = "Permissions"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    SubjectDisplayName = coalesce(Data -> SubjectDisplayName, get_data_Data -> SubjectDisplayName),
    SubjectDescriptor = coalesce(Data -> SubjectDescriptor, get_data_Data -> SubjectDescriptor),
    ChangedPermission = coalesce(Data -> ChangedPermission, get_data_Data -> ChangedPermission)

| alter //xdm mapping
    xdm.target.zone = coalesce(Data -> NamespaceName, get_data_Data -> NamespaceName),
    xdm.target.agent.identifier = coalesce(Data -> Token, get_data_Data -> Token),
    xdm.target.resource.type = if(Data -> SubjectDisplayName != null OR get_data_Data -> SubjectDisplayName != null, "Permission"),
    xdm.target.resource.value = coalesce(Data -> PermissionModifiedTo, get_data_Data -> PermissionModifiedTo),
    xdm.target.resource.name = if(ChangedPermission != null, ChangedPermission, get_data_Data = null, to_string(arraymap(Data -> EventSummary[], "@element" -> PermissionNames)), to_string(arraymap(get_data_Data -> eventSummary[], "@element" -> permissionNames))),
    xdm.target.user.groups = if(SubjectDescriptor = null, arraycreate(SubjectDisplayName)),
    xdm.target.user.upn = if(SubjectDescriptor != null, arrayindex(regextract(SubjectDescriptor, ".+\\+(.+)"),0)),
    xdm.target.user.username = if(SubjectDescriptor != null, SubjectDisplayName),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Pipelines events
filter Area = "Pipelines" OR _raw_log ->[0].data.Area = "Pipelines"
| call generic_devops_rule
| alter
    get_data_Data = get_data -> Data
| alter
    isResource = if(Data -> ResourceId != null OR get_data_Data -> ResourceId != null, to_boolean("True"), to_boolean("False"))
| alter //xdm mapping
    xdm.target.zone = coalesce(Data -> EnvironmentName, get_data_Data -> EnvironmentName),
    xdm.target.resource.type = if(isResource = True AND get_data_Data = null, Data -> ResourceType, isResource = True, get_data_Data -> ResourceType, to_string("Pipeline")),
    xdm.target.resource.id = if(isResource = True AND get_data_Data = null, Data -> ResourceId, isResource = True, get_data_Data -> ResourceId, get_data_Data = null, Data -> PipelineId, get_data_Data -> PipelineId),
    xdm.source.process.name = coalesce(Data -> CallerProcedure, get_data_Data -> callerProcedure),
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS;

//Fallback to whats not in the event types we are mapping
filter Area NOT IN ("Licensing", "Extension", "Git", "Group", "Library", "Token", "Policy", "Project", "Release", "Permissions", "Pipelines") AND _raw_log ->[0].data.Area NOT IN ("Licensing", "Extension", "Git", "Group", "Library", "Token", "Policy", "Project", "Release", "Permissions", "Pipelines")
| call generic_devops_rule;


[MODEL: dataset = "atlassian_bitbucket_raw", content_id="bitbucket"]
alter
    affected_objects_id = arraystring(arraymap(json_extract_array(_raw_log, "$.affectedObjects"), "@element" -> id), ", "),
    affected_objects_name = arraystring(arraymap(json_extract_array(_raw_log, "$.affectedObjects"), "@element" -> name), ", "),
    affected_objects_type = arraystring(arraymap(json_extract_array(_raw_log, "$.affectedObjects"), "@element" -> type), ", "),
    changed_values_from = arraystring(arraymap(json_extract_array(_raw_log, "$.changedValues"), "@element" -> from), ", "),
    changed_values_to = arraystring(arraymap(json_extract_array(_raw_log, "$.changedValues"), "@element" -> to), ", "),
    extra_data = object_create("Area",_raw_log -> auditType.area,"Category", _raw_log -> auditType.category, "Level",_raw_log -> auditType.level,"Method",_raw_log -> method),
    source_ip_address = _raw_log -> source,
    intermediate_ip_address = parsed_fields -> Load_balancer_proxy_IP_address
| alter
    parsed_fields = object_merge(extra_data ,parsed_fields),
    ipv4 = if(source_ip_address ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",source_ip_address ,null),
    ipv6 = if(source_ip_address ~= "^((?:[a-fA-F\d]{0,4}\:){2,7}[a-fA-F\d]{0,4})$",source_ip_address ,null),
    intermediate_ipv4 = if(intermediate_ip_address ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",intermediate_ip_address ,null),
    intermediate_ipv6 = if(intermediate_ip_address ~= "^((?:[a-fA-F\d]{0,4}\:){2,7}[a-fA-F\d]{0,4})$",intermediate_ip_address ,null)
| alter
    xdm.target.resource.id = affected_objects_id,
    xdm.target.resource.name = affected_objects_name,
    xdm.target.resource.type = affected_objects_type,
    xdm.event.type = _raw_log -> auditType.action,
    xdm.source.user.identifier = _raw_log -> author.id,
    xdm.source.user.username = _raw_log -> author.name,
    xdm.target.resource_before.value = changed_values_from,
    xdm.target.resource.value = changed_values_to,
    xdm.source.ipv4 = ipv4,
    xdm.source.ipv6 = ipv6,
    xdm.intermediate.ipv4 = intermediate_ipv4,
    xdm.intermediate.ipv6 = intermediate_ipv6,
    xdm.observer.name = _raw_log -> system,
    xdm.event.description = parsed_fields;


[RULE: Cisco_Umbrella_Cloud_Security_Log_Type content_id="cisco-umbrella-cloud-security"]
alter Log_Fields = split(_raw_log, "\",")
| alter Log_Fields = arraymap(Log_Fields, trim("@element", "\""))
| alter logType = if(_log_source_file_path contains "dnslogs", "DNS", _log_source_file_path contains "proxylogs", "Proxy", _log_source_file_path contains "auditlogs", "Admin Audit");
[MODEL: dataset = cisco_umbrella_raw, content_id="cisco-umbrella-cloud-security"]
// Mapping DNS Logs
call Cisco_Umbrella_Cloud_Security_Log_Type
| filter logType = "DNS"
| alter
        Query_Type = uppercase(arrayindex(regextract(arrayindex(Log_Fields, 6), "\(([^\)]+)\)"),0)),
        Response_Code = arrayindex(Log_Fields, 7)
| alter
        xdm.event.type = logType,
        xdm.source.host.hostname = arrayindex(Log_Fields, 1),
        xdm.source.ipv4 = if(arrayindex(Log_Fields, 3) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 3), null),
        xdm.source.ipv6 = if(arrayindex(Log_Fields, 3) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 3), null),
        xdm.intermediate.ipv4 = if(arrayindex(Log_Fields, 4) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 4), null),
        xdm.intermediate.ipv6 = if(arrayindex(Log_Fields, 4) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 4), null),
        xdm.observer.action = arrayindex(Log_Fields, 5),
        xdm.network.dns.dns_question.type = if (Query_Type = "A",XDM_CONST.DNS_RECORD_TYPE_A, Query_Type = "AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, Query_Type = "AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, Query_Type = "APL",XDM_CONST.DNS_RECORD_TYPE_APL, Query_Type = "CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, Query_Type = "CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, Query_Type = "CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, Query_Type = "CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, Query_Type = "CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, Query_Type = "CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, Query_Type = "DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, Query_Type = "DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, Query_Type = "DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, Query_Type = "DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, Query_Type = "DS",XDM_CONST.DNS_RECORD_TYPE_DS, Query_Type = "EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, Query_Type = "EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, Query_Type = "HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, Query_Type = "HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, Query_Type = "HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, Query_Type = "IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, Query_Type = "KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, Query_Type = "KX",XDM_CONST.DNS_RECORD_TYPE_KX, Query_Type = "LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, Query_Type = "MX",XDM_CONST.DNS_RECORD_TYPE_MX, Query_Type = "NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, Query_Type = "NS",XDM_CONST.DNS_RECORD_TYPE_NS, Query_Type = "NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, Query_Type = "NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, Query_Type = "NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, Query_Type = "OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, Query_Type = "PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, Query_Type = "RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, Query_Type = "RP",XDM_CONST.DNS_RECORD_TYPE_RP, Query_Type = "SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, Query_Type = "SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, Query_Type = "SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, Query_Type = "SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, Query_Type = "SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, Query_Type = "SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, Query_Type = "TA",XDM_CONST.DNS_RECORD_TYPE_TA, Query_Type = "TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, Query_Type = "TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, Query_Type = "TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, Query_Type = "TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, Query_Type = "URI",XDM_CONST.DNS_RECORD_TYPE_URI, Query_Type = "ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(Query_Type)),
        xdm.network.dns.response_code = if(Response_Code = "NOERROR",XDM_CONST.DNS_RESPONSE_CODE_NO_ERROR ,Response_Code = "FORMERR",XDM_CONST.DNS_RESPONSE_CODE_FORMAT_ERROR,Response_Code = "SERVFAIL",XDM_CONST.DNS_RESPONSE_CODE_SERVER_FAILURE,Response_Code = "NXDOMAIN",XDM_CONST.DNS_RESPONSE_CODE_NON_EXISTENT_DOMAIN,Response_Code = "NOTIMP",XDM_CONST.DNS_RESPONSE_CODE_NOT_IMPLEMENTED,Response_Code = "REFUSED",XDM_CONST.DNS_RESPONSE_CODE_QUERY_REFUSED,Response_Code = "YXDOMAIN",XDM_CONST.DNS_RESPONSE_CODE_NAME_EXISTS_WHEN_IT_SHOULD_NOT,Response_Code = "YXRRSET",XDM_CONST.DNS_RESPONSE_CODE_RR_SET_EXISTS_WHEN_IT_SHOULD_NOT,Response_Code = "NXRRSET",XDM_CONST.DNS_RESPONSE_CODE_RR_SET_THAT_SHOULD_EXIST_DOES_NOT,Response_Code = "NOTAUTH",XDM_CONST.DNS_RESPONSE_CODE_SERVER_NOT_AUTHORITATIVE_FOR_ZONE,Response_Code = "NOTZONE",XDM_CONST.DNS_RESPONSE_CODE_NAME_NOT_CONTAINED_IN_ZONE,Response_Code = "BADVERS",XDM_CONST.DNS_RESPONSE_CODE_BAD_OPT_VERSION,Response_Code = "BADSIG",XDM_CONST.DNS_RESPONSE_CODE_TSIG_SIGNATURE_FAILURE,Response_Code = "BADKEY",XDM_CONST.DNS_RESPONSE_CODE_KEY_NOT_RECOGNIZED,Response_Code = "BADTIME",XDM_CONST.DNS_RESPONSE_CODE_SIGNATURE_OUT_OF_TIME_WINDOW,Response_Code = "BADMODE",XDM_CONST.DNS_RESPONSE_CODE_BAD_TKEY_MODE,Response_Code = "BADNAME",XDM_CONST.DNS_RESPONSE_CODE_DUPLICATE_KEY_NAME, Response_Code = "BADALG",XDM_CONST.DNS_RESPONSE_CODE_ALGORITHM_NOT_SUPPORTED,Response_Code = "BADTRUNC",XDM_CONST.DNS_RESPONSE_CODE_BAD_TRUNCATION, to_string(Response_Code)),
        xdm.network.dns.dns_question.name = rtrim(arrayindex(Log_Fields, 8), "\."),
        xdm.event.description = arrayindex(Log_Fields, 9),
        xdm.network.dns.opcode = to_integer(arrayindex(regextract(arrayindex(Log_Fields, 6), "(\d+)\s*\("),0)),
        xdm.alert.subcategory = arrayindex(Log_Fields, 12);
// Mapping Proxy Logs
call Cisco_Umbrella_Cloud_Security_Log_Type
| filter logType = "Proxy"
| alter
        Status_Code = arrayindex(Log_Fields, 10),
        AV_Detections = arrayindex(Log_Fields, 16),
        AMP_Malware_Name = arrayindex(Log_Fields, 19),
        Request_Method = arrayindex(Log_Fields, 25)
| alter
        xdm.event.type = logType,
        xdm.source.host.hostname = arrayindex(Log_Fields, 1),
        xdm.source.ipv4 = if(arrayindex(Log_Fields, 2) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 2), null),
        xdm.source.ipv6 = if(arrayindex(Log_Fields, 2) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 2), null),
        xdm.intermediate.ipv4 = if(arrayindex(Log_Fields, 3) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 3), null),
        xdm.intermediate.ipv6 = if(arrayindex(Log_Fields, 3) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 3), null),
        xdm.target.ipv4 = if(arrayindex(Log_Fields, 4) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 4), null),
        xdm.target.ipv6 =if(arrayindex(Log_Fields, 4) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 4), null),
        xdm.network.http.content_type = arrayindex(Log_Fields, 5),
        xdm.observer.action = arrayindex(Log_Fields, 6),
        xdm.network.http.url = arrayindex(Log_Fields, 7),
        xdm.network.http.referrer = arrayindex(Log_Fields, 8),
        xdm.source.user_agent = arrayindex(Log_Fields, 9),
        xdm.network.http.response_code = if(Status_Code = "100", XDM_CONST.HTTP_RSP_CODE_CONTINUE, Status_Code = "101", XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS, Status_Code = "102", XDM_CONST.HTTP_RSP_CODE_PROCESSING, Status_Code = "103", XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS, Status_Code = "200", XDM_CONST.HTTP_RSP_CODE_OK, Status_Code = "201", XDM_CONST.HTTP_RSP_CODE_CREATED, Status_Code = "202", XDM_CONST.HTTP_RSP_CODE_ACCEPTED, Status_Code = "203", XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION, Status_Code = "204", XDM_CONST.HTTP_RSP_CODE_NO_CONTENT, Status_Code = "205", XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT, Status_Code = "206", XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT, Status_Code = "207", XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS, Status_Code = "208", XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED, Status_Code = "226", XDM_CONST.HTTP_RSP_CODE_IM_USED, Status_Code = "300", XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES, Status_Code = "301", XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY, Status_Code = "302", XDM_CONST.HTTP_RSP_CODE_FOUND, Status_Code = "303", XDM_CONST.HTTP_RSP_CODE_SEE_OTHER, Status_Code = "304", XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED, Status_Code = "305", XDM_CONST.HTTP_RSP_CODE_USE_PROXY, Status_Code = "307", XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT, Status_Code = "308", XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT, Status_Code = "400", XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST, Status_Code = "401", XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED, Status_Code = "402", XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED, Status_Code = "403", XDM_CONST.HTTP_RSP_CODE_FORBIDDEN, Status_Code = "404", XDM_CONST.HTTP_RSP_CODE_NOT_FOUND, Status_Code = "405", XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED, Status_Code = "406", XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE, Status_Code = "407", XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED, Status_Code = "408", XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT, Status_Code = "409", XDM_CONST.HTTP_RSP_CODE_CONFLICT, Status_Code = "410", XDM_CONST.HTTP_RSP_CODE_GONE, Status_Code = "411", XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED, Status_Code = "412", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED, Status_Code = "413", XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE, Status_Code = "414", XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG, Status_Code = "415", XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE, Status_Code = "416", XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE, Status_Code = "417", XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED, Status_Code = "421", XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST, Status_Code = "422", XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT, Status_Code = "423", XDM_CONST.HTTP_RSP_CODE_LOCKED, Status_Code = "424", XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY, Status_Code = "425", XDM_CONST.HTTP_RSP_CODE_TOO_EARLY, Status_Code = "426", XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED, Status_Code = "428", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED, Status_Code = "429", XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS, Status_Code = "431", XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE, Status_Code = "451", XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS, Status_Code = "500", XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR, Status_Code = "501", XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED, Status_Code = "502", XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY, Status_Code = "503", XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE, Status_Code = "504", XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT, Status_Code = "505", XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED, Status_Code = "506", XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES, Status_Code = "507", XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE, Status_Code = "508", XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED, Status_Code = "511", XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED, Status_Code = null, null, to_string(Status_Code)),
        xdm.target.file.sha256 = arrayindex(Log_Fields, 14),
        xdm.target.application.name = arrayindex(Log_Fields, 17),
        xdm.alert.name = if(AV_Detections != null and AV_Detections != "", AV_Detections, AMP_Malware_Name != null and AMP_Malware_Name != "", AMP_Malware_Name, null),
        xdm.alert.subcategory = arrayindex(Log_Fields, 22),
        xdm.network.http.method = if(Request_Method = "ACL", XDM_CONST.HTTP_METHOD_ACL, Request_Method = "BASELINE_CONTROL", XDM_CONST.HTTP_METHOD_BASELINE_CONTROL , Request_Method = "BIND", XDM_CONST.HTTP_METHOD_BIND, Request_Method = "CHECKIN", XDM_CONST.HTTP_METHOD_CHECKIN, Request_Method = "CHECKOUT", XDM_CONST.HTTP_METHOD_CHECKOUT, Request_Method = "CONNECT", XDM_CONST.HTTP_METHOD_CONNECT, Request_Method = "COPY", XDM_CONST.HTTP_METHOD_COPY, Request_Method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE, Request_Method = "GET", XDM_CONST.HTTP_METHOD_GET, Request_Method = "HEAD", XDM_CONST.HTTP_METHOD_HEAD, Request_Method = "LABEL", XDM_CONST.HTTP_METHOD_LABEL, Request_Method = "LINK", XDM_CONST.HTTP_METHOD_LINK, Request_Method = "LOCK", XDM_CONST.HTTP_METHOD_LOCK, Request_Method = "MERGE", XDM_CONST.HTTP_METHOD_MERGE, Request_Method = "MKACTIVITY", XDM_CONST.HTTP_METHOD_MKACTIVITY, Request_Method = "MKCALENDAR", XDM_CONST.HTTP_METHOD_MKCALENDAR, Request_Method = "MKCOL", XDM_CONST.HTTP_METHOD_MKCOL, Request_Method = "MKREDIRECTREF", XDM_CONST.HTTP_METHOD_MKREDIRECTREF, Request_Method = "MKWORKSPACE", XDM_CONST.HTTP_METHOD_MKWORKSPACE, Request_Method = "MOVE", XDM_CONST.HTTP_METHOD_MOVE, Request_Method = "OPTIONS", XDM_CONST.HTTP_METHOD_OPTIONS, Request_Method = "ORDERPATCH", XDM_CONST.HTTP_METHOD_ORDERPATCH, Request_Method = "PATCH", XDM_CONST.HTTP_METHOD_PATCH, Request_Method = "POST", XDM_CONST.HTTP_METHOD_POST, Request_Method = "PRI", XDM_CONST.HTTP_METHOD_PRI, Request_Method = "PROPFIND", XDM_CONST.HTTP_METHOD_PROPFIND, Request_Method = "PROPPATCH", XDM_CONST.HTTP_METHOD_PROPPATCH, Request_Method = "PUT", XDM_CONST.HTTP_METHOD_PUT, Request_Method = "REBIND", XDM_CONST.HTTP_METHOD_REBIND, Request_Method = "REPORT", XDM_CONST.HTTP_METHOD_REPORT, Request_Method = "SEARCH", XDM_CONST.HTTP_METHOD_SEARCH, Request_Method = "TRACE", XDM_CONST.HTTP_METHOD_TRACE, Request_Method = "UNBIND", XDM_CONST.HTTP_METHOD_UNBIND, Request_Method = "UNCHECKOUT", XDM_CONST.HTTP_METHOD_UNCHECKOUT, Request_Method = "UNLINK", XDM_CONST.HTTP_METHOD_UNLINK, Request_Method = "UNLOCK", XDM_CONST.HTTP_METHOD_UNLOCK, Request_Method = "UPDATE", XDM_CONST.HTTP_METHOD_UPDATE, Request_Method = "UPDATEREDIRECTREF", XDM_CONST.HTTP_METHOD_UPDATEREDIRECTREF, Request_Method = "VERSION_CONTROL", XDM_CONST.HTTP_METHOD_VERSION_CONTROL, Request_Method = null, null, to_string(Request_Method)),
        xdm.target.file.filename = arrayindex(Log_Fields, 28),
        xdm.network.rule = if(arrayindex(Log_Fields, 30) != null and arrayindex(Log_Fields, 30) != "", arrayindex(Log_Fields, 30), arrayindex(Log_Fields, 29) != null and arrayindex(Log_Fields, 29) != "", arrayindex(Log_Fields, 29), null);
// Mapping Admin Audit logs
call Cisco_Umbrella_Cloud_Security_Log_Type
| filter logType = "Admin Audit" and array_length(Log_Fields) > 8
| alter
        xdm.event.type = logType,
        xdm.event.id = arrayindex(Log_Fields, 0),
        xdm.source.user.upn = arrayindex(Log_Fields, 2),
        xdm.source.user.username = arrayindex(Log_Fields, 3),
        xdm.observer.action = arrayindex(Log_Fields, 5),
        xdm.source.ipv4 = if(arrayindex(Log_Fields, 6) ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arrayindex(Log_Fields, 6), null),
        xdm.source.ipv6 = if(arrayindex(Log_Fields, 6) ~= "[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}", arrayindex(Log_Fields, 6), null),
        xdm.target.resource_before.value = arrayindex(Log_Fields, 7),
        xdm.target.resource.value = arrayindex(Log_Fields, 8);


[MODEL: dataset = cisco_thousandeyes_raw, content_id="ciscothousandeyes"]

/* Activity Audit logs (https://developer.cisco.com/docs/thousandeyes/list-activity-log-events/)  */
filter SOURCE_LOG_TYPE = "AuditEvents"
| alter 
    affected_resources_count = array_length(resources -> []), 
    user_ipv4 = if(ipAddress ~= "(?:\d{1,3}\.){3}\d{1,3}", ipAddress),
    user_ipv6 = if(ipAddress ~= "(?:[a-fA-F\d]{0,4}\:){2,7}[a-fA-F\d]{0,4}", ipAddress)
| alter 
    xdm.event.original_event_type = event,
    xdm.event.type = SOURCE_LOG_TYPE,
    xdm.source.host.ipv4_public_addresses = if(user_ipv4 != null and not incidr(user_ipv4, "10.0.0.0/8") and not incidr(user_ipv4, "172.16.0.0/12") and not incidr(user_ipv4, "192.168.0.0/16") and not incidr(user_ipv4, "127.0.0.0/8") and not incidr(user_ipv4, "169.254.0.0/16") and not incidr(user_ipv4, "100.64.0.0/10"), arraycreate(user_ipv4)),
    xdm.source.ipv4 = user_ipv4,
    xdm.source.ipv6 = user_ipv6,
    xdm.source.user.groups = arrayfilter(arraycreate(accountGroupName, aid), "@element" != null),
    xdm.source.user.identifier = uid,
    xdm.source.user.username = coalesce(arrayindex(regextract(user, "\(([^\)]+)\)"), 0), user), // extract user email from within parentheses, e.g., "API Sandbox User (noreply@thousandeyes.com)"
    xdm.target.resource.name = if(affected_resources_count > 0, arraystring(arraydistinct(arraymap(resources -> [], "@element" -> name)), ",")),
    xdm.target.resource.type = if(affected_resources_count > 0, arraystring(arraydistinct(arraymap(resources -> [], "@element" -> type)), ","));

/* Alerts (https://developer.cisco.com/docs/thousandeyes/alert/)  */
filter SOURCE_LOG_TYPE = "Alerts"  
| alter 
    xdm.alert.original_alert_id = id,
    xdm.alert.severity = alertSeverity,
    xdm.alert.category = alertType,
    xdm.event.duration = to_integer(duration),
    xdm.event.is_completed = if(alertState = "clear"),
    xdm.event.original_event_type = alertType,
    xdm.event.type = SOURCE_LOG_TYPE,
    xdm.network.rule = alertRuleId;


[MODEL: dataset=corelight_zeek_raw, content_id="corelightzeek"]
// DNS Logs
filter _path ~= "dns"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.observer.name = _system_name, 
    xdm.observer.version = version,
    xdm.event.type = _path,
    xdm.event.id = uid,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)), 
    xdm.event.duration = to_integer(rtt),
    xdm.network.dns.is_response = to_boolean(rejected),
    xdm.network.dns.dns_question.name = query,
    xdm.network.dns.dns_question.type = if(qtype_name="A",XDM_CONST.DNS_RECORD_TYPE_A, qtype_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, qtype_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, qtype_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, qtype_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, qtype_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, qtype_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, qtype_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, qtype_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, qtype_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, qtype_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, qtype_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, qtype_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, qtype_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, qtype_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, qtype_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, qtype_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, qtype_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, qtype_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, qtype_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, qtype_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, qtype_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, qtype_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, qtype_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, qtype_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, qtype_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, qtype_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, qtype_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, qtype_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, qtype_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, qtype_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, qtype_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, qtype_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, qtype_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, qtype_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, qtype_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, qtype_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, qtype_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, qtype_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, qtype_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, qtype_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, qtype_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, qtype_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, qtype_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, qtype_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, qtype_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, qtype_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(qtype_name)),
    xdm.network.dns.dns_resource_record.name = to_string(rcode),
    xdm.network.dns.dns_resource_record.type = if(rcode_name="A",XDM_CONST.DNS_RECORD_TYPE_A, rcode_name="AAAA",XDM_CONST.DNS_RECORD_TYPE_AAAA, rcode_name="AFSDB",XDM_CONST.DNS_RECORD_TYPE_AFSDB, rcode_name="APL",XDM_CONST.DNS_RECORD_TYPE_APL, rcode_name="CAA",XDM_CONST.DNS_RECORD_TYPE_CAA, rcode_name="CDNSKEY",XDM_CONST.DNS_RECORD_TYPE_CDNSKEY, rcode_name="CDS",XDM_CONST.DNS_RECORD_TYPE_CDS, rcode_name="CERT",XDM_CONST.DNS_RECORD_TYPE_CERT, rcode_name="CNAME",XDM_CONST.DNS_RECORD_TYPE_CNAME, rcode_name="CSYNC",XDM_CONST.DNS_RECORD_TYPE_CSYNC, rcode_name="DHCID",XDM_CONST.DNS_RECORD_TYPE_DHCID, rcode_name="DLV",XDM_CONST.DNS_RECORD_TYPE_DLV, rcode_name="DNAME",XDM_CONST.DNS_RECORD_TYPE_DNAME, rcode_name="DNSKEY",XDM_CONST.DNS_RECORD_TYPE_DNSKEY, rcode_name="DS",XDM_CONST.DNS_RECORD_TYPE_DS, rcode_name="EUI48",XDM_CONST.DNS_RECORD_TYPE_EUI48, rcode_name="EUI64",XDM_CONST.DNS_RECORD_TYPE_EUI64, rcode_name="HINFO",XDM_CONST.DNS_RECORD_TYPE_HINFO, rcode_name="HIP",XDM_CONST.DNS_RECORD_TYPE_HIP, rcode_name="HTTPS",XDM_CONST.DNS_RECORD_TYPE_HTTPS, rcode_name="IPSECKEY",XDM_CONST.DNS_RECORD_TYPE_IPSECKEY, rcode_name="KEY",XDM_CONST.DNS_RECORD_TYPE_KEY, rcode_name="KX",XDM_CONST.DNS_RECORD_TYPE_KX, rcode_name="LOC",XDM_CONST.DNS_RECORD_TYPE_LOC, rcode_name="MX",XDM_CONST.DNS_RECORD_TYPE_MX, rcode_name="NAPTR",XDM_CONST.DNS_RECORD_TYPE_NAPTR, rcode_name="NS",XDM_CONST.DNS_RECORD_TYPE_NS, rcode_name="NSEC",XDM_CONST.DNS_RECORD_TYPE_NSEC, rcode_name="NSEC3",XDM_CONST.DNS_RECORD_TYPE_NSEC3, rcode_name="NSEC3PARAM",XDM_CONST.DNS_RECORD_TYPE_NSEC3PARAM, rcode_name="OPENPGPKEY",XDM_CONST.DNS_RECORD_TYPE_OPENPGPKEY, rcode_name="PTR",XDM_CONST.DNS_RECORD_TYPE_PTR, rcode_name="RRSIG",XDM_CONST.DNS_RECORD_TYPE_RRSIG, rcode_name="RP",XDM_CONST.DNS_RECORD_TYPE_RP, rcode_name="SIG",XDM_CONST.DNS_RECORD_TYPE_SIG, rcode_name="SMIMEA",XDM_CONST.DNS_RECORD_TYPE_SMIMEA, rcode_name="SOA",XDM_CONST.DNS_RECORD_TYPE_SOA, rcode_name="SRV",XDM_CONST.DNS_RECORD_TYPE_SRV, rcode_name="SSHFP",XDM_CONST.DNS_RECORD_TYPE_SSHFP, rcode_name="SVCB",XDM_CONST.DNS_RECORD_TYPE_SVCB, rcode_name="TA",XDM_CONST.DNS_RECORD_TYPE_TA, rcode_name="TKEY",XDM_CONST.DNS_RECORD_TYPE_TKEY, rcode_name="TLSA",XDM_CONST.DNS_RECORD_TYPE_TLSA, rcode_name="TSIG",XDM_CONST.DNS_RECORD_TYPE_TSIG, rcode_name="TXT",XDM_CONST.DNS_RECORD_TYPE_TXT, rcode_name="URI",XDM_CONST.DNS_RECORD_TYPE_URI, rcode_name="ZONEMD",XDM_CONST.DNS_RECORD_TYPE_ZONEMD, to_string(rcode_name)),
    //xdm.source.agent.identifier = trans_id,
    xdm.network.dns.dns_resource_record.value = answers;
// HTTP Logs
filter _path ~= "http"
| alter
    status_code_string = to_string(status_code)
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.name = _system_name,
    xdm.observer.version = version,
    xdm.event.id = uid,
    xdm.network.http.referrer = referrer,
    xdm.network.http.url = uri,
    xdm.observer.unique_identifier = tags,
    xdm.source.user_agent = user_agent,
    xdm.network.http.method = if(method = "ACL", XDM_CONST.HTTP_METHOD_ACL, method = "BASELINE_CONTROL", XDM_CONST.HTTP_METHOD_BASELINE_CONTROL , method = "BIND", XDM_CONST.HTTP_METHOD_BIND, method = "CHECKIN", XDM_CONST.HTTP_METHOD_CHECKIN, method = "CHECKOUT", XDM_CONST.HTTP_METHOD_CHECKOUT, method = "CONNECT", XDM_CONST.HTTP_METHOD_CONNECT, method = "COPY", XDM_CONST.HTTP_METHOD_COPY, method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE, method = "GET", XDM_CONST.HTTP_METHOD_GET, method = "HEAD", XDM_CONST.HTTP_METHOD_HEAD, method = "LABEL", XDM_CONST.HTTP_METHOD_LABEL, method = "LINK", XDM_CONST.HTTP_METHOD_LINK, method = "LOCK", XDM_CONST.HTTP_METHOD_LOCK, method = "MERGE", XDM_CONST.HTTP_METHOD_MERGE, method = "MKACTIVITY", XDM_CONST.HTTP_METHOD_MKACTIVITY, method = "MKCALENDAR", XDM_CONST.HTTP_METHOD_MKCALENDAR, method = "MKCOL", XDM_CONST.HTTP_METHOD_MKCOL, method = "MKREDIRECTREF", XDM_CONST.HTTP_METHOD_MKREDIRECTREF, method = "MKWORKSPACE", XDM_CONST.HTTP_METHOD_MKWORKSPACE, method = "MOVE", XDM_CONST.HTTP_METHOD_MOVE, method = "OPTIONS", XDM_CONST.HTTP_METHOD_OPTIONS, method = "ORDERPATCH", XDM_CONST.HTTP_METHOD_ORDERPATCH, method = "PATCH", XDM_CONST.HTTP_METHOD_PATCH, method = "POST", XDM_CONST.HTTP_METHOD_POST, method = "PRI", XDM_CONST.HTTP_METHOD_PRI, method = "PROPFIND", XDM_CONST.HTTP_METHOD_PROPFIND, method = "PROPPATCH", XDM_CONST.HTTP_METHOD_PROPPATCH, method = "PUT", XDM_CONST.HTTP_METHOD_PUT, method = "REBIND", XDM_CONST.HTTP_METHOD_REBIND, method = "REPORT", XDM_CONST.HTTP_METHOD_REPORT, method = "SEARCH", XDM_CONST.HTTP_METHOD_SEARCH, method = "TRACE", XDM_CONST.HTTP_METHOD_TRACE, method = "UNBIND", XDM_CONST.HTTP_METHOD_UNBIND, method = "UNCHECKOUT", XDM_CONST.HTTP_METHOD_UNCHECKOUT, method = "UNLINK", XDM_CONST.HTTP_METHOD_UNLINK, method = "UNLOCK", XDM_CONST.HTTP_METHOD_UNLOCK, method = "UPDATE", XDM_CONST.HTTP_METHOD_UPDATE, method = "UPDATEREDIRECTREF", XDM_CONST.HTTP_METHOD_UPDATEREDIRECTREF, method = "VERSION_CONTROL", XDM_CONST.HTTP_METHOD_VERSION_CONTROL, method = null, null, to_string(method)),
    xdm.network.http.response_code = if(status_code_string = "100", XDM_CONST.HTTP_RSP_CODE_CONTINUE, status_code_string = "101", XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS, status_code_string = "102", XDM_CONST.HTTP_RSP_CODE_PROCESSING, status_code_string = "103", XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS, status_code_string = "200", XDM_CONST.HTTP_RSP_CODE_OK, status_code_string = "201", XDM_CONST.HTTP_RSP_CODE_CREATED, status_code_string = "202", XDM_CONST.HTTP_RSP_CODE_ACCEPTED, status_code_string = "203", XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION, status_code_string = "204", XDM_CONST.HTTP_RSP_CODE_NO_CONTENT, status_code_string = "205", XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT, status_code_string = "206", XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT, status_code_string = "207", XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS, status_code_string = "208", XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED, status_code_string = "226", XDM_CONST.HTTP_RSP_CODE_IM_USED, status_code_string = "300", XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES, status_code_string = "301", XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY, status_code_string = "302", XDM_CONST.HTTP_RSP_CODE_FOUND, status_code_string = "303", XDM_CONST.HTTP_RSP_CODE_SEE_OTHER, status_code_string = "304", XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED, status_code_string = "305", XDM_CONST.HTTP_RSP_CODE_USE_PROXY, status_code_string = "307", XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT, status_code_string = "308", XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT, status_code_string = "400", XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST, status_code_string = "401", XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED, status_code_string = "402", XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED, status_code_string = "403", XDM_CONST.HTTP_RSP_CODE_FORBIDDEN, status_code_string = "404", XDM_CONST.HTTP_RSP_CODE_NOT_FOUND, status_code_string = "405", XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED, status_code_string = "406", XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE, status_code_string = "407", XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED, status_code_string = "408", XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT, status_code_string = "409", XDM_CONST.HTTP_RSP_CODE_CONFLICT, status_code_string = "410", XDM_CONST.HTTP_RSP_CODE_GONE, status_code_string = "411", XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED, status_code_string = "412", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED, status_code_string = "413", XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE, status_code_string = "414", XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG, status_code_string = "415", XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE, status_code_string = "416", XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE, status_code_string = "417", XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED, status_code_string = "421", XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST, status_code_string = "422", XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT, status_code_string = "423", XDM_CONST.HTTP_RSP_CODE_LOCKED, status_code_string = "424", XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY, status_code_string = "425", XDM_CONST.HTTP_RSP_CODE_TOO_EARLY, status_code_string = "426", XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED, status_code_string = "428", XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED, status_code_string = "429", XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS, status_code_string = "431", XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE, status_code_string = "451", XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS, status_code_string = "500", XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR, status_code_string = "501", XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED, status_code_string = "502", XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY, status_code_string = "503", XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE, status_code_string = "504", XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT, status_code_string = "505", XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED, status_code_string = "506", XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES, status_code_string = "507", XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE, status_code_string = "508", XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED, status_code_string = "511", XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED, status_code_string = null, null, to_string(status_code_string)),
    xdm.source.host.hostname = origin,
    xdm.source.sent_bytes = to_integer(request_body_len),
    xdm.target.host.hostname = host,
    xdm.target.sent_bytes = to_integer(response_body_len);
// NTLM Logs
filter _path ~= "ntlm"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.auth.ntlm.user_name = username,
    xdm.auth.ntlm.hostname = hostname,
    xdm.auth.ntlm.domain = domainname,
    xdm.auth.ntlm.dns_domain = server_dns_computer_name,
    xdm.auth.ntlm.dns_three = server_tree_name,
    xdm.event.outcome = if(success = true, XDM_CONST.OUTCOME_SUCCESS, success = false, XDM_CONST.OUTCOME_FAILED, success = null, null, "UNKNOWN");
// Syslogs 
filter _path ~= "syslog"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.description = message,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)),
    xdm.alert.severity = severity,
    xdm.intermediate.process.name = facility;
// Conn Logs
filter _path ~= "conn"
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.operation_sub_type = conn_state,
    xdm.network.application_protocol = service,
    xdm.network.ip_protocol = if(proto=lowercase("HOPOPT"),XDM_CONST.IP_PROTOCOL_HOPOPT, proto=lowercase("ICMP"),XDM_CONST.IP_PROTOCOL_ICMP, proto=lowercase("IGMP"),XDM_CONST.IP_PROTOCOL_IGMP, proto=lowercase("GGP"),XDM_CONST.IP_PROTOCOL_GGP, proto=lowercase("IP"),XDM_CONST.IP_PROTOCOL_IP, proto=lowercase("ST"),XDM_CONST.IP_PROTOCOL_ST, proto=lowercase("TCP"),XDM_CONST.IP_PROTOCOL_TCP, proto=lowercase("CBT"),XDM_CONST.IP_PROTOCOL_CBT, proto=lowercase("EGP"),XDM_CONST.IP_PROTOCOL_EGP, proto=lowercase("IGP"),XDM_CONST.IP_PROTOCOL_IGP, proto=lowercase("BBN_RCC_MON"),XDM_CONST.IP_PROTOCOL_BBN_RCC_MON, proto=lowercase("NVP_II"),XDM_CONST.IP_PROTOCOL_NVP_II, proto=lowercase("PUP"),XDM_CONST.IP_PROTOCOL_PUP, proto=lowercase("ARGUS"),XDM_CONST.IP_PROTOCOL_ARGUS, proto=lowercase("EMCON"),XDM_CONST.IP_PROTOCOL_EMCON, proto=lowercase("XNET"),XDM_CONST.IP_PROTOCOL_XNET, proto=lowercase("CHAOS"),XDM_CONST.IP_PROTOCOL_CHAOS, proto=lowercase("UDP"),XDM_CONST.IP_PROTOCOL_UDP, proto=lowercase("MUX"),XDM_CONST.IP_PROTOCOL_MUX, proto=lowercase("DCN_MEAS"),XDM_CONST.IP_PROTOCOL_DCN_MEAS, proto=lowercase("HMP"),XDM_CONST.IP_PROTOCOL_HMP, proto=lowercase("PRM"),XDM_CONST.IP_PROTOCOL_PRM, proto=lowercase("XNS_IDP"),XDM_CONST.IP_PROTOCOL_XNS_IDP, proto=lowercase("TRUNK_1"),XDM_CONST.IP_PROTOCOL_TRUNK_1, proto=lowercase("TRUNK_2"),XDM_CONST.IP_PROTOCOL_TRUNK_2, proto=lowercase("LEAF_1"),XDM_CONST.IP_PROTOCOL_LEAF_1, proto=lowercase("LEAF_2"),XDM_CONST.IP_PROTOCOL_LEAF_2, proto=lowercase("RDP"),XDM_CONST.IP_PROTOCOL_RDP, proto=lowercase("IRTP"),XDM_CONST.IP_PROTOCOL_IRTP, proto=lowercase("ISO_TP4"),XDM_CONST.IP_PROTOCOL_ISO_TP4, proto=lowercase("NETBLT"),XDM_CONST.IP_PROTOCOL_NETBLT, proto=lowercase("MFE_NSP"),XDM_CONST.IP_PROTOCOL_MFE_NSP, proto=lowercase("MERIT_INP"),XDM_CONST.IP_PROTOCOL_MERIT_INP, proto=lowercase("DCCP"),XDM_CONST.IP_PROTOCOL_DCCP, proto=lowercase("3PC"),XDM_CONST.IP_PROTOCOL_3PC, proto=lowercase("IDPR"),XDM_CONST.IP_PROTOCOL_IDPR, proto=lowercase("XTP"),XDM_CONST.IP_PROTOCOL_XTP, proto=lowercase("DDP"),XDM_CONST.IP_PROTOCOL_DDP, proto=lowercase("IDPR_CMTP"),XDM_CONST.IP_PROTOCOL_IDPR_CMTP, proto=lowercase("TP"),XDM_CONST.IP_PROTOCOL_TP, proto=lowercase("IL"),XDM_CONST.IP_PROTOCOL_IL, proto=lowercase("IPV6"),XDM_CONST.IP_PROTOCOL_IPV6, proto=lowercase("SDRP"),XDM_CONST.IP_PROTOCOL_SDRP, proto=lowercase("IPV6_ROUTE"),XDM_CONST.IP_PROTOCOL_IPV6_ROUTE, proto=lowercase("IPV6_FRAG"),XDM_CONST.IP_PROTOCOL_IPV6_FRAG, proto=lowercase("IDRP"),XDM_CONST.IP_PROTOCOL_IDRP, proto=lowercase("RSVP"),XDM_CONST.IP_PROTOCOL_RSVP, proto=lowercase("GRE"),XDM_CONST.IP_PROTOCOL_GRE, proto=lowercase("DSR"),XDM_CONST.IP_PROTOCOL_DSR, proto=lowercase("BNA"),XDM_CONST.IP_PROTOCOL_BNA, proto=lowercase("ESP"),XDM_CONST.IP_PROTOCOL_ESP, proto=lowercase("AH"),XDM_CONST.IP_PROTOCOL_AH, proto=lowercase("I_NLSP"),XDM_CONST.IP_PROTOCOL_I_NLSP, proto=lowercase("SWIPE"),XDM_CONST.IP_PROTOCOL_SWIPE, proto=lowercase("NARP"),XDM_CONST.IP_PROTOCOL_NARP, proto=lowercase("MOBILE"),XDM_CONST.IP_PROTOCOL_MOBILE, proto=lowercase("TLSP"),XDM_CONST.IP_PROTOCOL_TLSP, proto=lowercase("SKIP"),XDM_CONST.IP_PROTOCOL_SKIP, proto=lowercase("IPV6_ICMP"),XDM_CONST.IP_PROTOCOL_IPV6_ICMP, proto=lowercase("IPV6_NONXT"),XDM_CONST.IP_PROTOCOL_IPV6_NONXT, proto=lowercase("IPV6_OPTS"),XDM_CONST.IP_PROTOCOL_IPV6_OPTS, proto=lowercase("CFTP"),XDM_CONST.IP_PROTOCOL_CFTP, proto=lowercase("SAT_EXPAK"),XDM_CONST.IP_PROTOCOL_SAT_EXPAK, proto=lowercase("KRYPTOLAN"),XDM_CONST.IP_PROTOCOL_KRYPTOLAN, proto=lowercase("RVD"),XDM_CONST.IP_PROTOCOL_RVD, proto=lowercase("IPPC"),XDM_CONST.IP_PROTOCOL_IPPC, proto=lowercase("SAT_MON"),XDM_CONST.IP_PROTOCOL_SAT_MON, proto=lowercase("VISA"),XDM_CONST.IP_PROTOCOL_VISA, proto=lowercase("IPCV"),XDM_CONST.IP_PROTOCOL_IPCV, proto=lowercase("CPNX"),XDM_CONST.IP_PROTOCOL_CPNX, proto=lowercase("CPHB"),XDM_CONST.IP_PROTOCOL_CPHB, proto=lowercase("WSN"),XDM_CONST.IP_PROTOCOL_WSN, proto=lowercase("PVP"),XDM_CONST.IP_PROTOCOL_PVP, proto=lowercase("BR_SAT_MON"),XDM_CONST.IP_PROTOCOL_BR_SAT_MON, proto=lowercase("SUN_ND"),XDM_CONST.IP_PROTOCOL_SUN_ND, proto=lowercase("WB_MON"),XDM_CONST.IP_PROTOCOL_WB_MON, proto=lowercase("WB_EXPAK"),XDM_CONST.IP_PROTOCOL_WB_EXPAK, proto=lowercase("ISO_IP"),XDM_CONST.IP_PROTOCOL_ISO_IP, proto=lowercase("VMTP"),XDM_CONST.IP_PROTOCOL_VMTP, proto=lowercase("SECURE_VMTP"),XDM_CONST.IP_PROTOCOL_SECURE_VMTP, proto=lowercase("VINES"),XDM_CONST.IP_PROTOCOL_VINES, proto=lowercase("TTP"),XDM_CONST.IP_PROTOCOL_TTP, proto=lowercase("NSFNET_IGP"),XDM_CONST.IP_PROTOCOL_NSFNET_IGP, proto=lowercase("DGP"),XDM_CONST.IP_PROTOCOL_DGP, proto=lowercase("TCF"),XDM_CONST.IP_PROTOCOL_TCF, proto=lowercase("EIGRP"),XDM_CONST.IP_PROTOCOL_EIGRP, proto=lowercase("OSPFIGP"),XDM_CONST.IP_PROTOCOL_OSPFIGP, proto=lowercase("SPRITE_RPC"),XDM_CONST.IP_PROTOCOL_SPRITE_RPC, proto=lowercase("LARP"),XDM_CONST.IP_PROTOCOL_LARP, proto=lowercase("MTP"),XDM_CONST.IP_PROTOCOL_MTP, proto=lowercase("AX25"),XDM_CONST.IP_PROTOCOL_AX25, proto=lowercase("IPIP"),XDM_CONST.IP_PROTOCOL_IPIP, proto=lowercase("MICP"),XDM_CONST.IP_PROTOCOL_MICP, proto=lowercase("SCC_SP"),XDM_CONST.IP_PROTOCOL_SCC_SP, proto=lowercase("ETHERIP"),XDM_CONST.IP_PROTOCOL_ETHERIP, proto=lowercase("ENCAP"),XDM_CONST.IP_PROTOCOL_ENCAP, proto=lowercase("GMTP"),XDM_CONST.IP_PROTOCOL_GMTP, proto=lowercase("IFMP"),XDM_CONST.IP_PROTOCOL_IFMP, proto=lowercase("PNNI"),XDM_CONST.IP_PROTOCOL_PNNI, proto=lowercase("PIM"),XDM_CONST.IP_PROTOCOL_PIM, proto=lowercase("ARIS"),XDM_CONST.IP_PROTOCOL_ARIS, proto=lowercase("SCPS"),XDM_CONST.IP_PROTOCOL_SCPS, proto=lowercase("QNX"),XDM_CONST.IP_PROTOCOL_QNX, proto=lowercase("AN"),XDM_CONST.IP_PROTOCOL_AN, proto=lowercase("IPCOMP"),XDM_CONST.IP_PROTOCOL_IPCOMP, proto=lowercase("COMPAQ_PEER"),XDM_CONST.IP_PROTOCOL_COMPAQ_PEER, proto=lowercase("IPX_IN_IP"),XDM_CONST.IP_PROTOCOL_IPX_IN_IP, proto=lowercase("VRRP"),XDM_CONST.IP_PROTOCOL_VRRP, proto=lowercase("PGM"),XDM_CONST.IP_PROTOCOL_PGM, proto=lowercase("L2TP"),XDM_CONST.IP_PROTOCOL_L2TP, proto=lowercase("DDX"),XDM_CONST.IP_PROTOCOL_DDX, proto=lowercase("IATP"),XDM_CONST.IP_PROTOCOL_IATP, proto=lowercase("STP"),XDM_CONST.IP_PROTOCOL_STP, proto=lowercase("SRP"),XDM_CONST.IP_PROTOCOL_SRP, proto=lowercase("UTI"),XDM_CONST.IP_PROTOCOL_UTI, proto=lowercase("SMP"),XDM_CONST.IP_PROTOCOL_SMP, proto=lowercase("SM"),XDM_CONST.IP_PROTOCOL_SM, proto=lowercase("PTP"),XDM_CONST.IP_PROTOCOL_PTP, proto=lowercase("ISIS"),XDM_CONST.IP_PROTOCOL_ISIS, proto=lowercase("FIRE"),XDM_CONST.IP_PROTOCOL_FIRE, proto=lowercase("CRTP"),XDM_CONST.IP_PROTOCOL_CRTP, proto=lowercase("CRUDP"),XDM_CONST.IP_PROTOCOL_CRUDP, proto=lowercase("SSCOPMCE"),XDM_CONST.IP_PROTOCOL_SSCOPMCE, proto=lowercase("IPLT"),XDM_CONST.IP_PROTOCOL_IPLT, proto=lowercase("SPS"),XDM_CONST.IP_PROTOCOL_SPS, proto=lowercase("PIPE"),XDM_CONST.IP_PROTOCOL_PIPE, proto=lowercase("SCTP"),XDM_CONST.IP_PROTOCOL_SCTP, proto=lowercase("FC"),XDM_CONST.IP_PROTOCOL_FC, proto=lowercase("RSVP_E2E_IGNORE"),XDM_CONST.IP_PROTOCOL_RSVP_E2E_IGNORE, proto=lowercase("MOBILITY"),XDM_CONST.IP_PROTOCOL_MOBILITY, proto=lowercase("UDPLITE"),XDM_CONST.IP_PROTOCOL_UDPLITE, proto=lowercase("MPLS_IN_IP"),XDM_CONST.IP_PROTOCOL_MPLS_IN_IP,to_string(proto)), 
    xdm.event.duration = to_integer(multiply(to_float(duration), 1000)),
    xdm.source.sent_bytes = to_integer(orig_bytes),
    xdm.source.sent_packets = to_integer(orig_pkts),
    xdm.target.sent_bytes = to_integer(resp_bytes),
    xdm.target.sent_packets = to_integer(resp_pkts)
| alter
    xdm.event.outcome = if(proto = "tcp" and to_integer(resp_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "tcp" and to_integer(resp_pkts) = 0, XDM_CONST.OUTCOME_FAILED, proto = "icmp" and to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_SUCCESS, proto = "icmp" and to_integer(resp_pkts) = 0 and to_integer(orig_bytes) > 0, XDM_CONST.OUTCOME_FAILED, to_integer(resp_pkts) > 0 and to_integer(orig_bytes) > 0 and to_integer(resp_bytes) > 0 and to_integer(orig_pkts) > 0, XDM_CONST.OUTCOME_SUCCESS, null);
// Kerberos
filter _path ~= "kerberos"
| alter
   lower_c_cipher = lowercase(cipher) 
| alter 
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.version = version,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.outcome = if(success = true, XDM_CONST.OUTCOME_SUCCESS, success = false, XDM_CONST.OUTCOME_FAILED , success = null, null, to_string(success)),
    xdm.auth.kerberos_tgt.msg_type = if(request_type = "AS", XDM_CONST.KERBEROS_MSG_TYPE_AS_REQ, request_type = "TGS", XDM_CONST.KERBEROS_MSG_TYPE_TGS_REQ, request_type = "AP", XDM_CONST.KERBEROS_MSG_TYPE_AP_REQ, request_type = "RESERVED16", XDM_CONST.KERBEROS_MSG_TYPE_RESERVED16, request_type = "SAFE", XDM_CONST.KERBEROS_MSG_TYPE_SAFE, request_type = "PRIV", XDM_CONST.KERBEROS_MSG_TYPE_PRIV, request_type = "CRED", XDM_CONST.KERBEROS_MSG_TYPE_CRED, request_type = "ERROR", XDM_CONST.KERBEROS_MSG_TYPE_ERROR, request_type = null, null, to_string(request_type)),    
    xdm.auth.kerberos_tgt.spn_values = arraycreate(service),
    xdm.auth.kerberos_tgt.cname_values = arraycreate(client),
    xdm.auth.kerberos_tgt.encryption_type = if(lower_c_cipher ~= "des[\-|\_]cbc[\-|\_]crc", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_CRC, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes128[\_|\-]cts[\_|\-]hmac[\_|\-]sha256[\_|\-]128", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha1[\_|\-]96", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96, lower_c_cipher ~= "aes256[\_|\-]cts[\_|\-]hmac[\_|\-]sha384[\_|\-]192", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA384_192, lower_c_cipher ~= "camellia128[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA128_CTS_CMAC, lower_c_cipher ~= "camellia256[\_|\-]cts[\_|\-]cmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_CAMELLIA256_CTS_CMAC, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_MD5, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_RAW, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1[\_|\-]kd", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1_KD, lower_c_cipher ~= "des3[\_|\-]cbc[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES3_CBC_SHA1, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md4", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD4, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]md5", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD5, lower_c_cipher ~= "des[\_|\-]cbc[\_|\-]raw", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_RAW, lower_c_cipher ~= "des[\_|\-]ede3[\_|\-]cbc[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_EDE3_CBC_ENV_OID, lower_c_cipher ~= "des[\_|\-]hmac[\_|\-]sha1", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_HMAC_SHA1, lower_c_cipher ~= "dsawithsha1[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DSAWITHSHA1_CMSOID, lower_c_cipher ~= "md5withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_MD5WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "rc2cbc[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC2CBC_ENVOID, lower_c_cipher ~= "rc4[\_|\-]hmac[\_|\-]exp", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC_EXP, lower_c_cipher ~= "rc4[\_|\-]hmac", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC, lower_c_cipher ~= "rsaencryption[\_|\-]envoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAENCRYPTION_ENVOID, lower_c_cipher ~= "rsaes[\_|\-]oaep[\_|\-]env[\_|\-]oid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RSAES_OAEP_ENV_OID, lower_c_cipher ~= "sha1withrsaencryption[\_|\-]cmsoid", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SHA1WITHRSAENCRYPTION_CMSOID, lower_c_cipher ~= "subkey[\_|\-]keymaterial", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_SUBKEY_KEYMATERIAL, to_string(lower_c_cipher));
// DCE_RPC
filter _path ~= "dce_rpc"
| alter
    xdm.source.ipv4 = if(id_orig_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_orig_h, null),
    xdm.source.ipv6 = if(id_orig_h ~= ":", id_orig_h, null),
    xdm.target.ipv4 = if(id_resp_h ~= "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", id_resp_h, null),
    xdm.target.ipv6 = if(id_resp_h ~= ":", id_resp_h, null),
    xdm.source.port = to_integer(id_orig_p),
    xdm.target.port = to_integer(id_resp_p),
    xdm.event.type = _path,
    xdm.observer.name = _system_name,
    xdm.event.id = uid,
    xdm.event.duration = to_integer(rtt),
    xdm.intermediate.application.name = named_pipe,
    xdm.source.user.identifier = endpoint,
    xdm.event.outcome_reason = operation,
    xdm.observer.version = version;


[MODEL: dataset=duo_duo_raw, content_id="duoadminapi"]
filter
    eventtype = "authentication"
| alter
    os_version = json_extract_scalar(access_device, "$.os_version"),
    os = lowercase(json_extract_scalar(access_device, "$.os")),
    browser = json_extract_scalar(access_device, "$.browser"),
    browser_version = json_extract_scalar(access_device, "$.browser_version"),
    access_device_ip = json_extract_scalar(access_device, "$.ip"),
    result_enum = lowercase(result),
    establish_factor = if(factor = "phone_call", "voice", factor = "sms_refresh", "sms", factor = "sms_passcode", "sms", factor = "duo_mobile_passcode", "application", factor = "duo_push", "application", factor = "duo_mobile_passcode", "application", factor = "bypass_code", "temp_token", factor = "hardware_token", "hardware_token", factor = "yubikey_code", "hardware_token", factor = "yubikey_passcode", "hardware_token", factor = "WebAuthn Security Key ", "hardware_token", factor = "WebAuthn Credential", "hardware_token", factor = "WebAuthn Chrome Touch ID", "hardware_token", factor = "utf_token", "hardware_token", factor = "digipass_go_7_token", "hardware_token", factor = "remembered_device", "trusted_login", factor = "trusted_mobile_authenticator", "trusted_login", reason = "trusted_network", "trusted_login", reason = "allowed_by_policy", "trusted_login", reason = "authentication_trusted_by_risk_based_remembered_devices", "trusted_login", reason = "allow_unenrolled_user_on_trusted_network", "trusted_login", reason = "trusted_location", "trusted_login", reason = "bypass_user", "trusted_login", factor = "not_available", "Generic SSO", factor = "passcode", "Generic SSO", null),
    establish_reason = if(reason = "invalid_management_certificate_collection_state", "malformed_request", reason = "user_provided_invalid_certificate", "malformed_request", reason = "invalid_referring_hostname_provided", "malformed_request", reason = "no_web_referer_match", "malformed_request", reason = "no_referring_hostname_provided", "malformed_request", reason = "no_duo_certificate_present", "malformed_request", reason = "no_activated_duo_mobile_account", "user_does_not_exist", reason = "deny_unenrolled_user", "user_does_not_exist", reason = "user_disabled", "account_expired_or_disabled", reason = "locked_out", "account_locked", reason = "factor_restricted", "auth_policy_access_violation", reason = "user_not_in_permitted_group", "auth_login_restrictions", reason = "endpoint_health_data_missing", "device_security_issues", reason = "invalid_device", "device_security_issues", reason = "platform_restricted", "device_security_issues", reason = "endpoint_is_not_healthy", "device_security_issues", reason = "no_screen_lock", "device_security_issues", reason = "endpoint_is_not_in_management_system", "device_security_issues", reason = "endpoint_is_not_trusted", "device_security_issues", reason = "could_not_determine_if_endpoint_was_trusted", "device_security_issues", reason = "version_restricted", "device_security_issues", reason = "touchid_disabled", "device_security_issues", reason = "no_disk_encryption", "device_security_issues", reason = "endpoint_failed_google_verification", "device_security_issues", reason = "verification_code_missing", "mfa_failure", reason = "invalid_passcode", "mfa_failure", reason = "no_response", "mfa_expired", reason = "no_keys_pressed", "mfa_expired", reason = "call_timed_out", "mfa_expired", reason = "user_deny", "user_reject", reason = "user_cancelled", "user_cancelled", reason = "user_mistake", "user_cancelled", reason = "error", "failed_login", reason = null, null, to_string(reason)),
    first_last_name = split(to_string(regextract(email, "(.*)@")), "."),
    auth_device_ip = json_extract_scalar(auth_device, "$.ip")
| alter
    source_ipv4 = if(access_device_ip !~= ":", access_device_ip, null),
    source_ipv6 = if(access_device_ip ~= ":", access_device_ip, null), 
    intermediate_ipv4 = if(auth_device_ip !~= ":", auth_device_ip, null),
    intermediate_ipv6 = if(auth_device_ip ~= ":", auth_device_ip, null),
    establish_os_category = if(os ~= "fedora|ubuntu|chrome|mac|windows|linux|debian", "Computer", os ~= "ios|blackberry|android|phone", "Mobile", os ~= "tizen", "IOT", os = null, null, to_string(os)),
    alert_risks_check = if(reason = "location_restricted", "risky_signin", reason = "anomalous_push", "risky_signin", reason = "anonymous_ip", "risky_signin", result = "fraud", "risky_signin", null)
| alter
    xdm.target.ipv4 = "",
    xdm.target.ipv6 = "",
    xdm.source.port = if(source_ipv4 = "0.0.0.0", null, to_integer(0)),
    xdm.target.port = if(source_ipv4 = "0.0.0.0", null, to_integer(0)),
    xdm.source.user.user_type = XDM_CONST.USER_TYPE_REGULAR,
    xdm.logon.type = XDM_CONST.LOGON_TYPE_INTERACTIVE,
    xdm.event.id = _id,
    xdm.source.host.device_id = json_extract_scalar(access_device, "$.epkey"),
    xdm.event.operation = if(reason in ("remembered_device", "trusted_network", "authentication_trusted_by_risk_based_remembered_devices"), "Login", "MFA"),
    xdm.event.original_event_type = event_type,
    xdm.event.operation_sub_type = establish_factor,
    xdm.event.outcome_reason = establish_reason,
    xdm.source.host.device_category = establish_os_category,
    xdm.source.application.name = coalesce(browser, ood_software),
    xdm.source.application.version = browser_version,
    xdm.source.user.first_name = to_string(replex(arrayindex(first_last_name, 0), "\[\"", "")),
    xdm.source.user.last_name = to_string(replex(arrayindex(first_last_name, 1), "\"\]", "")),
    xdm.target.resource.id = json_extract_scalar(application, "$.key"),
    xdm.target.resource.name = json_extract_scalar(application, "$.name"),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.alert.risks = if(alert_risks_check = null, null, arraycreate(alert_risks_check)),
    xdm.session_context_id = txid,
    xdm.auth.mfa.client_details = adaptive_trust_assessments,
    xdm.source.user.groups = user -> groups[],
    xdm.source.user.sam_account_name = alias,
    xdm.intermediate.ipv4 = intermediate_ipv4,
    xdm.intermediate.ipv6 = intermediate_ipv6,
    xdm.source.user.identifier = json_extract_scalar(user, "$.key"),
    xdm.source.host.hostname = json_extract_scalar(access_device, "$.hostname"),
    xdm.source.ipv4 = source_ipv4,
    xdm.source.ipv6 = source_ipv6,
    xdm.source.location.city = json_extract_scalar(access_device, "$.location.city"),
    xdm.source.location.country = json_extract_scalar(access_device, "$.location.country"),
    xdm.source.location.region = json_extract_scalar(access_device, "$.location.state"),
    xdm.source.host.os_family = if(os contains "windows", XDM_CONST.OS_FAMILY_WINDOWS, os contains "mac", XDM_CONST.OS_FAMILY_MACOS, os contains "linux", XDM_CONST.OS_FAMILY_LINUX, os contains "android", XDM_CONST.OS_FAMILY_ANDROID, os contains "ios", XDM_CONST.OS_FAMILY_IOS, os contains "ubuntu", XDM_CONST.OS_FAMILY_UBUNTU, os contains "debian", XDM_CONST.OS_FAMILY_DEBIAN, os contains "fedora", XDM_CONST.OS_FAMILY_FEDORA, os contains "centos", XDM_CONST.OS_FAMILY_CENTOS, os contains "chrome", XDM_CONST.OS_FAMILY_CHROMEOS, os contains "solaris", XDM_CONST.OS_FAMILY_SOLARIS, os contains "scada", XDM_CONST.OS_FAMILY_SCADA, os = null, null, to_string(os)),
    xdm.source.host.os = concat(os, " ", os_version),
    xdm.event.type = if(source_ipv4 = "0.0.0.0", null, eventtype),
    xdm.observer.name = host,
    xdm.source.user.username = json_extract_scalar(user, "$.name"),
    xdm.source.user.upn = email,
    xdm.event.outcome = if(result_enum contains "failure", XDM_CONST.OUTCOME_FAILED, result_enum contains "success", XDM_CONST.OUTCOME_SUCCESS, result_enum contains "denied", XDM_CONST.OUTCOME_FAILED, result_enum contains "fraud", XDM_CONST.OUTCOME_FAILED, result_enum = null, null, to_string(result)),
    xdm.observer.action = result_enum,
    xdm.network.http.browser = concat(browser, " ", browser_version),
    xdm.intermediate.host.hostname = json_extract_scalar(auth_device, "$.name"),
    xdm.intermediate.location.country = json_extract_scalar(auth_device, "$.location.country"),
    xdm.intermediate.location.city = json_extract_scalar(auth_device, "$.location.city"),
    xdm.intermediate.location.region = json_extract_scalar(auth_device, "$.location.state"),
    xdm.auth.mfa.method = factor,
    xdm.auth.service = "IDP";
filter
    eventtype = "administrator"
| alter
        source_ipv4 = arrayindex(regextract(json_extract_scalar(description, "$.ip_address"), "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),0),
        source_ipv6 = arrayindex(regextract(json_extract_scalar(description, "$.ip_address"), "([a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5}[a-fA-F0-9\:]{1,5})"),0)
| alter
    xdm.event.operation = action,
    xdm.event.description = description,
    xdm.target.resource.name = object,
    xdm.source.user.username = username,
    xdm.event.type = eventtype,
    xdm.observer.name = HOST,
    xdm.target.user.upn = json_extract_scalar(description, "$.email"),
    xdm.auth.auth_method = json_extract_scalar(description, "$.factor"),
    xdm.source.ipv4 =  source_ipv4,
    xdm.source.ipv6 = if(source_ipv4 = null, source_ipv6, null),
    xdm.target.user.groups  = arraycreate(coalesce(json_extract_scalar(description, "$.role"),""));
filter
    eventtype = "telephony"
| alter
        xdm.observer.name = HOST,
        xdm.event.type = eventtype,
        xdm.auth.mfa.method = type,
        xdm.event.description = context,
        xdm.event.id = telephony_id,
        xdm.source.host.hostname = phone;


[MODEL: dataset=github_github_audit_raw, content_id="github"]
filter
    action in("oauth_application*","org_credential_authorization*")
| alter
    //_time = timestamp_seconds(to_integer(divide(created_at, 1000))),
    xdm.source.user.username = actor,
    xdm.source.location.country = json_extract_scalar(actor_location, "$.country_code"),
    xdm.event.operation = action;

filter
    action in("org*","role*","account*","advisory_credit*","billing*","business*","codespaces*","dependabot_alerts*","dependabot_alerts_new_repos*","dependabot_security_updates*","dependabot_security_updates_new_repos*","dependency_graph*","dependency_graph_new_repos*","discussion_post*","discussion_post_reply*","enterprise*","environment*","git*","hook*","integration_installation_request*","ip_allow_list*","ip_allow_list_entry*","issue*","marketplace_agreement_signature*","marketplace_listing*","members_can_create_pages*","org_secret_scanning_custom_pattern*","organization_label*","packages*","payment_method*","profile_picture*","project*","protected_branch*","pull_request*","pull_request_review*","pull_request_review_comment*","repo*","repository_advisory*","repository_content_analysis*","repository_dependency_graph*","repository_secret_scanning*","repository_secret_scanning_custom_pattern*","repository_secret_scanning_push_protection*","repository_vulnerability_alert*","repository_vulnerability_alerts*","secret_scanning*","secret_scanning_new_repos*","sponsors*","team*","team_discussions*","workflows*")
| alter
    //_time = timestamp_seconds(to_integer(divide(created_at, 1000))),
    xdm.source.location.country = json_extract_scalar(actor_location, "$.country_code"),
    xdm.target.user.username = org,
    xdm.target.cloud.project = repo,
    xdm.source.user.username = actor,
    xdm.event.operation = action;


[MODEL: dataset = gitlab_gitlab_raw, content_id="gitlab"]
alter
    xdm.event.id = to_string(id),
    xdm.source.user.identifier = to_string(author_id),
    xdm.target.resource.id = to_string(entity_id),
    xdm.target.resource.type = entity_type,
    xdm.source.user.username = json_extract_scalar(details, "$.author_name"),
    xdm.target.resource.sub_type = json_extract_scalar(details, "$.target_type"),
    xdm.target.resource.name = json_extract_scalar(details, "$.target_details"),
    xdm.event.description = json_extract_scalar(details, "$.custom_message"),
    xdm.source.ipv4 = json_extract_scalar(details, "$.ip_address"),
    xdm.target.resource_before.value = json_extract_scalar(details, "$.from"),
    xdm.target.resource.value = json_extract_scalar(details, "$.to"),
    xdm.event.operation = json_extract_scalar(details, "$.action"),
    xdm.event.type = json_extract_scalar(details, "$.action_type"),
    xdm.event.operation_sub_type = json_extract_scalar(details, "$.action_category"),
    xdm.observer.vendor = _vendor,
    xdm.observer.product = _product;


[MODEL: dataset=hello_world_raw, content_id="helloworld"]
alter
    xdm.event.id = to_string(id),
    xdm.event.description = description,
    xdm.source.user.identifier = json_extract_scalar(custom_details, "$.triggered_by_uuid"),
    xdm.target.port = t_port,
    xdm.network.protocol_layers = arraycreate(protocol);


[MODEL: dataset=jamf_pro_raw, content_id="jamf"]
alter
    outcome_result = coalesce(json_extract_scalar(Event, "$.successful"), json_extract_scalar(Event, "$.operationSuccessful"))
| alter
    xdm.target.resource.name = coalesce(json_extract_scalar(Event, "$.deviceName"), json_extract_scalar(Event, "$.computer.deviceName"), json_extract_scalar(Event, "$.name"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.deviceName")), ","), json_extract_scalar(Event, "$.targetDevice.deviceName"),arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.deviceName")), ",")),
    xdm.source.ipv4 = coalesce(json_extract_scalar(Event, "$.ipAddress"), json_extract_scalar(Event, "$.computer.ipAddress"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.ipAddress")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.ipAddress")), ",")),
    xdm.target.resource.id = coalesce(json_extract_scalar(Event, "$.jssID"), json_extract_scalar(Event, "$.computer.jssID"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.jssID")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.jssID")), ",")),
    xdm.target.resource.type = coalesce(json_extract_scalar(Event, "$.model"), json_extract_scalar(Event, "$.computer.model"), json_extract_scalar(Event, "$.targetDevice.model"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.model")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.model")), ",")),
    xdm.target.resource.sub_type = coalesce(json_extract_scalar(Event, "$.osVersion"), json_extract_scalar(Event, "$.computer.osVersion"), json_extract_scalar(Event, "$.targetDevice.osVersion"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.osVersion")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.osVersion")), ",")),
    xdm.source.user.username = coalesce(json_extract_scalar(Event, "$.username"), json_extract_scalar(Event, "$.patchPolicyName"), json_extract_scalar(Event, "$.authorizedUsername"), json_extract_scalar(Event, "$.targetUser.username"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.username")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.username")), ",")),
    xdm.event.id = json_extract_scalar(webhook, "$.id"),
    xdm.event.description = json_extract_scalar(webhook, "$.name"),
    xdm.event.type = json_extract_scalar(webhook, "$.webhookEvent"),
    xdm.event.outcome_reason = json_extract_scalar(Event, "$.trigger"),
    xdm.source.user.identifier = json_extract_scalar(Event, "$.patchPolicyId"),
    xdm.event.outcome = if(outcome_result = "false", XDM_CONST.OUTCOME_FAILED, outcome_result = "true", XDM_CONST.OUTCOME_SUCCESS, outcome_result = null, null, to_string(outcome_result)),
    xdm.event.operation_sub_type = json_extract_scalar(Event, "$.restAPIOperationType"),
    xdm.target.host.mac_addresses = arraycreate(coalesce(json_extract_scalar(Event, "$.wifiMacAddress"), json_extract_scalar(Event, "$.macAddress"), json_extract_scalar(Event, "$.computer.macAddress"), json_extract_scalar(Event, "$.targetDevice.wifiMacAddress"), "")),
    xdm.target.host.device_id = coalesce(json_extract_scalar(Event, "$.serialNumber"), json_extract_scalar(Event, "$.computer.serialNumber"), json_extract_scalar(Event, "$.targetDevice.serialNumber"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.serialNumber")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.serialNumber")), ",")),
    xdm.target.host.hardware_uuid = coalesce(json_extract_scalar(Event, "$.udid"), json_extract_scalar(Event, "$.computer.udid"), arraystring(arraymap (json_extract_array ("groupAddedDevices","$."), json_extract_scalar ("@element", "$.udid")), ","), arraystring(arraymap (json_extract_array ("groupRemovedDevices","$."), json_extract_scalar ("@element", "$.udid")), ","), json_extract_scalar(Event, "$.targetDevice.udid"));


[MODEL: dataset=atlassian_jira_raw, content_id="jira"]
alter

	jira_status_change = json_extract_scalar(changedValues, "$.changedTo")

| alter

	xdm.event.operation = summary,

	xdm.source.ipv4 = remoteAddress,

	xdm.source.user.username = authorKey,

	xdm.source.user.identifier = authorAccountId,

	xdm.event.operation_sub_type = category,

	xdm.target.user.identifier = json_extract_scalar(objectItem, "$.id"),

	xdm.target.user.username = json_extract_scalar(objectItem, "$.name"),

	xdm.target.resource.type = json_extract_scalar(objectItem, "$.typeName"),

	xdm.event.outcome = if(jira_status_change != null, XDM_CONST.OUTCOME_SUCCESS, jira_status_change = null, null),

	xdm.event.outcome_reason = jira_status_change;


[MODEL: dataset="prisma_cloud_raw", content_id="prismacloud"]
alter /* extract alert data (schema docs: https://pan.dev/prisma-cloud/api/cspm/get-alerts-v-2/) */
    alert_scanner_version = alertAdditionalInfo -> scannerVersion,
    policy_description = policy -> description,
    policy_labels = arraymap(policy -> labels[], trim("@element", "\"")),
    policy_name = policy -> name, 
    policy_cloudType = policy -> cloudType, 
    policy_policyId = policy -> policyId, 
    policy_policyType = policy -> policyType,  
    policy_severity = policy -> severity,
    policy_lastModifiedBy = policy -> lastModifiedBy, 
    policy_recommendation = policy -> recommendation,
    policy_mitre_compliance_metadata = arrayfilter(policy -> complianceMetadata[], "@element" -> sectionLabel = "MITRE ATT&CK"),
    resource_account = resource -> account, 
    resource_accountId = resource -> accountId, 
    resource_cloudaccountgroups = arraymap(resource -> cloudAccountGroups[], trim("@element", "\"")),
    resource_cloudaccountowners = trim(arraystring(resource -> cloudAccountOwners[], ","), "\""),
    resource_cloudType = resource -> cloudType, 
    resource_cloudServiceName = resource -> cloudServiceName,
    resource_data_zone = resource -> data.zone,
    resource_data_placement_availabilityZone = resource -> data.placement.availabilityZone,
    resource_data_snapshot_availabilityZone = resource -> data.snapshot.availabilityZone, // DB_SNAPSHOT resource type
    resource_data_availabilityZones_zoneName = arraystring(arraymap(resource -> data.availabilityZones[], "@element" -> zoneName), ","),
    resource_data_cidrBlock = resource -> data.cidrBlock,
    resource_data_ipCidrRange = resource -> data.ipCidrRange, // SUBNET resource type
    resource_data_association_publicIp = resource -> data.association.publicIp, // IFACE resource type
    resource_data_mac_address = resource -> data.macAddress, // IFACE resource type
    resource_data_dbname = resource -> data.dbname, // MANAGED_DBMS resource type 
    resource_data_snapshot_port = resource -> data.snapshot.port, // DB_SNAPSHOT resource type 
    resource_data_endpoint_port = resource -> data.endpoint.port, // MANAGED_DBMS resource type
    resource_data_endpoint = resource -> data.endpoint,
    resource_data_gatewayAddress = resource -> data.gatewayAddress, // SUBNET resource type
    resource_data_user = resource -> data.user, // IAM_CREDENTIAL_REPORT & IAM_USER resource types
    resource_data_host = resource -> data.host, // INSTANCE resource type
    resource_id = resource -> id, 
    resource_name = resource -> name, 
    resource_region = resource -> region, 
    resource_regionId = resource -> regionId, 
    resource_resourceType = resource -> resourceType, 
    resource_rrn = resource -> rrn,  
    resource_url = resource -> url
| alter // post extraction processing 
    cloud_type = uppercase(coalesce(policy_cloudType, resource_cloudType)), 
    cloud_region = coalesce(resource_regionId, resource_region),
    cloud_zone = coalesce(arrayindex(regextract(resource_data_zone, "zones\/([\w\-]+)"), 0), resource_data_zone, resource_data_placement_availabilityZone, resource_data_snapshot_availabilityZone, resource_data_availabilityZones_zoneName),
    hostname = if(resource_resourceType = "INSTANCE", resource_name),
    ip_address = if(resource_resourceType = "GCP_KUBERNETES_CLUSTER", resource_data_endpoint, coalesce(resource_data_host, resource_data_gatewayAddress, resource_data_association_publicIp)),
    port = to_integer(coalesce(resource_data_endpoint_port, resource_data_snapshot_port)),
    subnet_cidr_range = coalesce(resource_data_cidrBlock, resource_data_ipCidrRange), 
    mac_address = if(resource_data_mac_address != null, arraycreate(resource_data_mac_address)),
    mitre_tactics = arraydistinct(arraymap(policy_mitre_compliance_metadata, "@element" -> requirementId)),
    mitre_techniques = arraydistinct(arraymap(policy_mitre_compliance_metadata, "@element" -> sectionId))
| alter cloud_provider = if(cloud_type ~= "ALIBABA", XDM_CONST.CLOUD_PROVIDER_ALIBABA, cloud_type ~= "AWS|AMAZON", XDM_CONST.CLOUD_PROVIDER_AWS, cloud_type ~= "AZURE|MS|MICROSOFT", XDM_CONST.CLOUD_PROVIDER_AZURE, cloud_type ~= "GOOGLE|GCP", XDM_CONST.CLOUD_PROVIDER_GCP, cloud_type)
| alter // mappings 
    xdm.alert.name = policy_name, 
    xdm.alert.description = policy_description,
    xdm.alert.mitre_tactics = mitre_tactics, 
    xdm.alert.mitre_techniques = mitre_techniques,
    xdm.alert.original_alert_id = id,
    xdm.alert.original_threat_id = coalesce(policy_policyId, policyId), 
    xdm.alert.severity = policy_severity,
    xdm.database.name = resource_data_dbname,
    xdm.event.id = id,
    xdm.event.tags = policy_labels,
    xdm.event.original_event_type = policy_policyType,
    xdm.event.description = policy_recommendation, 
    xdm.event.outcome = status,
    xdm.event.outcome_reason = reason, 
    xdm.event.is_completed = if(status in ("resolved", "dismissed"), to_boolean("TRUE"), status in ("open", "snoozed"), to_boolean("FALSE")),
    xdm.intermediate.user.username = policy_lastModifiedBy, 
    xdm.network.rule = policy_name, 
    xdm.observer.version = alert_scanner_version,
    xdm.target.application.name = resource_cloudServiceName, 
    xdm.target.cloud.project = resource_account,
    xdm.target.cloud.provider = cloud_provider,
    xdm.target.cloud.region = cloud_region,
    xdm.target.cloud.zone = cloud_zone, 
    xdm.target.host.hostname = hostname,
    xdm.target.host.mac_addresses = mac_address,
    xdm.target.ipv4 = ip_address,
    xdm.target.port = port,
    xdm.target.resource.id = resource_id,
    xdm.target.resource.name = resource_rrn, 
    xdm.target.resource.type = resource_resourceType, 
    xdm.target.resource.value = resource_name, 
    xdm.target.resource.parent_id = resource_cloudaccountowners,
    xdm.target.subnet = subnet_cidr_range,
    xdm.target.url = resource_url,
    xdm.target.user.ou = resource_accountId,
    xdm.target.user.username = resource_data_user,
    xdm.target.user.groups = resource_cloudaccountgroups;


[MODEL: dataset=proofpoint_tap_raw, content_id="proofpointtap"]
alter
        fromAddress_string = if(fromAddress contains "[", arraystring(arraymap(fromAddress -> [], trim("@element", "\"")), ", "), fromAddress),
        threatID_string =  arraystring(arraymap(threatsinfomap -> [],  "@element"-> threatID), ", ")
| alter
    xdm.event.type = concat(_vendor," - ",_log_type),
    xdm.alert.description = coalesce(threatsInfoMap, threatURL),
    xdm.alert.original_threat_id = coalesce(threatID, threatID_string),
    xdm.alert.subcategory = coalesce(arraystring(arraymap (json_extract_array (threatsInfoMap,"$."), json_extract_scalar ("@element", "$.threatType")), ", "), classification, json_extract_scalar(threatsinfomap, "$['0'].classification")),
    xdm.alert.original_alert_id = GUID,
    xdm.alert.original_threat_name = coalesce(classification, json_extract_scalar(threatsinfomap, "$['0'].classification")),
    xdm.event.id = GUID,
    xdm.email.cc = arraymap(json_extract_array(ccAddresses, "$."), trim("@element", "\"")),
    xdm.email.sender = coalesce(fromAddress_string, sender),
    xdm.email.message_id = messageID,
    xdm.email.attachment.filename = arraystring(arraymap (json_extract_array (messageParts,"$."), json_extract_scalar ("@element", "$.filename")), ","),
    xdm.email.attachment.md5 = arraystring(arraymap (json_extract_array (messageParts,"$."), json_extract_scalar ("@element", "$.md5")), ","),
    xdm.email.attachment.sha256 = arraystring(arraymap (json_extract_array (messageParts,"$."), json_extract_scalar ("@element", "$.sha256")), ","),
    xdm.email.recipients = if(recipient contains "[", arraymap(recipient -> [], trim("@element", "\"")), arraycreate(recipient)),
    xdm.email.return_path = sender,
    xdm.email.subject = subject,
    xdm.intermediate.host.ipv4_addresses = arraycreate(senderIP),
    xdm.source.host.ipv4_addresses = arraycreate(clickIP),
    xdm.source.user_agent = userAgent,
    xdm.target.url = url,
    // Parse message messageTime
    xdm.email.delivery_timestamp = messageTime;


[MODEL:dataset = "servicenow_servicenow_raw", content_id="servicenow"]
// Transaction Logs
filter source_log_type = "syslog transactions"
|alter 
    // Event
    event_type = source_log_type,
    event_original_type = type,
    event_id = sys_id,
    event_duration_1 = to_integer(total_wait_time),
    event_duration_2 = to_integer(transaction_processing_time),
    event_description = object_create("Interaction ID", interaction_id, "Transaction Number", transaction_number, "Output Length", output_length, "Database Category", db_category, 
    "Additional Information", additional_info, "Debug Information", additional_debug_info),
    // IP Extraction
    remote_ip_ipv4 = arrayindex(regextract(remote_ip, "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),0),
    remote_ip_ipv6 = arrayindex(regextract(remote_ip , "(\w+\:\w+\:\w+\:\w+\:\w+\:\w+\:\w+\:\w+)"), 0),
    created_by = sys_created_by,
    system_identifier = system_id,
    source_user_agent = user_agent,
    target_url = url,
    session_con_id = session,
    protocol_layer = protocol,
    is_truncated = to_boolean(gzip),
    tmp_origin_scope_val = origin_scope -> value,
    tmp_trim_url = arrayindex(regextract(url, "table\/(\w+)\?"), 0),
    //database
    db_name = db_pool,
    response_time = to_integer(multiply(to_integer(sql_time),1000)) // Convert from ms to s
|alter
    table_name = to_string(if(len(`table`) >= 1, `table`, tmp_trim_url)),
    event_duration = to_integer(add(event_duration_1, event_duration_2)),
    application_name = if(tmp_origin_scope_val = "global", "Display Name: Global", concat("Display Name: ", app_scope," ,ID: ", tmp_origin_scope_val))
| alter
    xdm.event.id = event_id,
    xdm.event.type = event_type, 
    xdm.event.original_event_type = event_original_type,
    xdm.event.duration = event_duration,
    xdm.event.description = to_string(event_description),
    xdm.source.application.name = application_name,
    xdm.source.user.username = created_by,
    xdm.source.user.identifier = system_identifier,
    xdm.source.user_agent = source_user_agent,
    xdm.source.ipv4 = remote_ip_ipv4,
    xdm.source.ipv6 = remote_ip_ipv6, 
    xdm.target.url = target_url,
    xdm.database.tables = arraycreate(table_name), 
    xdm.database.response_time = response_time,
    xdm.database.name = db_name,
    xdm.network.dns.is_truncated = is_truncated, 
    xdm.network.application_protocol = protocol_layer, 
    xdm.session_context_id = session_con_id;

// Audit Logs
filter source_log_type not in ("syslog transactions", "case")
|alter // sys_audit: https://docs.servicenow.com/bundle/vancouver-platform-security/page/administer/time/concept/exploring-auditing.html#d227507e148
    xdm.database.tables = arraycreate(tablename), // Table that the audit record is for (for example, "incident")
    xdm.event.type = "AUDIT", 
    xdm.event.id = sys_id, // the record id of the audit record in sys_audit
    xdm.event.outcome_reason = reason, // Reason for the change (if any reason is associated with the change)
    xdm.session_context_id = documentkey, // the record id of the audited record in <tablename>
    xdm.source.user.username = user, // Name of the user who created the change. 
    xdm.target.resource_before.value = oldvalue, // Old value of the field change represented by this sys_audit record.
    xdm.target.resource.id = documentkey, // the record id of the audited record in <tablename>
    xdm.target.resource.name = fieldname, // Field that changed
    xdm.target.resource.type = tablename, // Table that the audit record is for (for example, "incident")
    xdm.target.resource.value = newvalue; // New value of the field change represented by this sys_audit record.


filter source_log_type = "case"
| alter
    get_impact = to_string(impact),
    get_urgency = to_string(urgency),
    get_escalation = to_string(escalation),
    get_category = to_string(category),
    get_priority = to_string(priority)
| alter
    check_impact = if(get_impact = "1", "impact:High", get_impact = "2", "impact:Medium", get_impact = "3", "impact:Low"),
    check_urgency = if(get_urgency = "1", "urgency:High", get_urgency = "2", "urgency:Medium", get_urgency = "3", "urgency:Low"),
    check_escalation = if(get_escalation = "0", "escalation:Normall", get_escalation = "1", "escalation:Moderate", get_escalation = "2", "escalation:High", get_escalation = "3", "escalation:Overdue")
| alter
    xdm.event.type = "Case",
    xdm.event.id = sys_id,
    xdm.alert.original_alert_id = coalesce(number, case_report),
    xdm.alert.risks = arraycreate(check_impact, check_urgency, check_escalation),
    xdm.event.description = object_create("active", active, "made_sla", made_sla, "knowledge", knowledge, "time_worked", time_worked, "upon_reject", upon_reject, "upon_approval", upon_approval, "follow_the_sun", follow_the_sun),
    xdm.event.outcome = if(
        approval = "approved", XDM_CONST.OUTCOME_SUCCESS, 
        approval = "cancelled", XDM_CONST.OUTCOME_FAILED, 
        approval = "duplicate", XDM_CONST.OUTCOME_UNKNOWN, 
        approval = "not_required", XDM_CONST.OUTCOME_UNKNOWN, 
        approval = "not requested", XDM_CONST.OUTCOME_UNKNOWN, 
        approval = "rejected", XDM_CONST.OUTCOME_FAILED, 
        approval = "requested", XDM_CONST.OUTCOME_PARTIAL, 
        approval = null, null, to_string(approval)
    ),
    xdm.event.outcome_reason = coalesce(resolution_code, approval),
    xdm.alert.category = if(get_category = "0", "Question", get_category = "1", "Issue", get_category = "2", "Feature"),
    xdm.alert.severity = if(get_priority = "1", "Low", get_priority = "2", "Moderate", get_priority = "3", "High", get_priority = "4", "Critical"),
    xdm.source.user.identifier = opened_by,
    xdm.source.user.domain = concat(sys_domain_path, sys_domain),
    xdm.alert.subcategory = if(subcategory != null, "Question", null),
    xdm.source.interface = contact_type,
    xdm.observer.content_version = to_string(object_create("N_of_CaseUpdates", sys_mod_count, "N_of_CaseReassign", reassignment_count)),
    xdm.database.tables = arraycreate(sys_class_name),
    xdm.source.user.username = sys_created_by,
    xdm.alert.description = coalesce(short_description, description),
    xdm.observer.name = assigned_to,
    xdm.observer.type = assignment_group,
    xdm.target.location.city = account -> city,
    xdm.target.location.country = account -> country,
    xdm.target.location.latitude = to_float(account -> latitude),
    xdm.target.location.longitude = to_float(account -> longitude),
    xdm.target.user.username = account -> name,
    xdm.target.user.identifier = account -> number,
    xdm.target.url = account -> website;


[MODEL: dataset=slack_slack_raw, content_id="slack"]
filter
    action not in ("user_login","user_logout")
| alter
    get_type = json_extract_scalar(entity, "$.type")
| alter
    xdm.event.id = id,
    xdm.event.operation = action,
    xdm.source.user.identifier = json_extract_scalar(actor, "$.user.id"),
    xdm.source.user.username = json_extract_scalar(actor, "$.user.name"),
    xdm.target.resource.type = get_type,
    xdm.source.user_agent = json_extract_scalar(context, "$.ua"),
    xdm.session_context_id = json_extract_scalar(context, "$.session_id"),
    xdm.source.ipv4 = json_extract_scalar(context, "$.ip_address"),
    xdm.target.resource.id = if(get_type = "channel", json_extract_scalar(entity, "$.channel.id"), get_type = "user", json_extract_scalar(entity, "$.user.id"), get_type = "file", json_extract_scalar(entity, "$.file.id"), get_type = "workspace", json_extract_scalar(entity, "$.workspace.id"), get_type = "enterprise", json_extract_scalar(entity, "$.enterprise.id"), get_type = "workflow", json_extract_scalar(entity, "$.workflow.id"), get_type = "message", json_extract_scalar(entity, "$.message.id"),get_type = "app", json_extract_scalar(entity, "$.app.id"),get_type = "usergroups", json_extract_scalar(entity, "$.usergroups.id"),get_type = "huddles", json_extract_scalar(entity, "$.huddles.id"), ""),
    xdm.target.resource.name = if(get_type = "channel", json_extract_scalar(entity, "$.channel.name"), get_type = "user", json_extract_scalar(entity, "$.user.name"), get_type = "file", json_extract_scalar(entity, "$.file.name"), get_type = "workspace", json_extract_scalar(entity, "$.workspace.name"), get_type = "enterprise", json_extract_scalar(entity, "$.enterprise.name"), get_type = "workflow", json_extract_scalar(entity, "$.workflow.name"), get_type = "message", json_extract_scalar(entity, "$.message.name"),get_type = "app", json_extract_scalar(entity, "$.app.name"),get_type = "usergroups", json_extract_scalar(entity, "$.usergroups.name"),get_type = "huddles", json_extract_scalar(entity, "$.huddles.name"), null);

filter
    action in ("user_login","user_logout")
| alter
    xdm.event.id = id,
    xdm.event.operation = action,
    xdm.source.user.identifier = json_extract_scalar(actor, "$.user.id"),
    xdm.source.user.username = json_extract_scalar(actor, "$.user.name"),
    xdm.target.user.identifier = json_extract_scalar(entity, "$.user.id"),
    xdm.target.user.username = json_extract_scalar(entity, "$.user.name"),
    xdm.target.application.name = json_extract_scalar(context, "$.app.name"),
    xdm.network.session_id = json_extract_scalar(context, "$.session_id"),
    xdm.source.ipv4 = json_extract_scalar(context, "$.ip_address");

