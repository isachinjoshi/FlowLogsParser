import csv
from enum import Enum

class FlowLogsParser:
    # look up table to keep parsed entries from the input 'lookup_table.csv' file
    tagsLookUpTable = {}
    # Enum to identify coloumn/field in the flow log e.g. 6th column is destination port
    class FlowLogColumns(Enum):
        VERSION = 0
        ACCOUNT_ID = 1
        INTERFACE_ID = 2
        SOURCE_ADDRESS = 3
        DESTINATION_ADDRESS = 4
        SOURCE_PORT = 5
        DESTINATION_PORT = 6
        PROTOCOL = 7
        PACKETS = 8
        BYTES = 9
        START_TIME = 10
        END_TIME = 11
        ACTION = 12
        LOG_STATUS = 13
        TCP_FLAGS = 14
        TYPE = 15
        PKT_SRCADDR = 16
        PKT_DSTADDR = 17
    # dictionary to store matched tags count
    tagsMatchCounts = {}
    # dictionary to store port + protocol match counts
    portAndProtocolMatchCounts = {}

    def GetProtocolName(self, protocolNumber):
        """
            :type protocolNumber: string
        """
        # protocol number to protocol name map
        protocolMapping = {
            "1": "ICMP",
            "2": "IGMP",
            "6": "TCP",
            "17": "UDP",
            "41": "IPv6",
            "47": "GRE",
            "50": "ESP",
            "51": "AH",
            "58": "ICMPv6",
            "89": "OSPF",
            "132": "SCTP"
        }

        if protocolNumber:
            return protocolMapping[protocolNumber]
        
        return ""

    def ParseLookupTable(self, filePath):
        """
            :type filePath: string
        """
        with open(filePath, mode = 'r') as file:
            reader = csv.DictReader(file)
        
            for row in reader:
                dstPort = None
                protocol = None
                tag = None
                dstPort = row['dstport'].strip()
                protocol = row['protocol'].strip().upper()
                tag = row['tag'].strip()

                if dstPort and protocol and tag:
                    FlowLogsParser.tagsLookUpTable[(dstPort, protocol)] = tag
                
    def ParseFlowLogs(self, filePath):
        """
            :type filePath: string
        """
        with open(filePath, "r") as file:
            for line in file:
                strippedLine = line.strip()
                if strippedLine:
                    logEntry = line.split()
                    protocol = None
                    destinationPort = None
                    protocol = self.GetProtocolName(logEntry[FlowLogsParser.FlowLogColumns.PROTOCOL.value].strip().upper())
                    destinationPort = logEntry[FlowLogsParser.FlowLogColumns.DESTINATION_PORT.value].strip()
                    if not any([protocol, destinationPort]):
                        continue
                    if (destinationPort, protocol) in FlowLogsParser.tagsLookUpTable:
                        # Count for port and protocol matches
                        if (destinationPort, protocol) not in FlowLogsParser.portAndProtocolMatchCounts:
                            FlowLogsParser.portAndProtocolMatchCounts[(destinationPort, protocol)] = 1
                        else:
                            FlowLogsParser.portAndProtocolMatchCounts[(destinationPort, protocol)] += 1
                        tag = FlowLogsParser.tagsLookUpTable[(destinationPort, protocol)]
                        
                        # Count for tags matches
                        if tag not in FlowLogsParser.tagsMatchCounts:
                            FlowLogsParser.tagsMatchCounts[tag] = 1
                        else:
                            FlowLogsParser.tagsMatchCounts[tag] += 1
                    else:
                        if "Untagged" not in FlowLogsParser.tagsMatchCounts:
                            FlowLogsParser.tagsMatchCounts["Untagged"] = 1
                        else:
                            FlowLogsParser.tagsMatchCounts["Untagged"] += 1
                        
flowLogsParser = FlowLogsParser()
lookupTableFilePath = "_lookup_table.csv"
flowLogsParser.ParseLookupTable(lookupTableFilePath)
flowFogFilePath = "flow_logs.csv"
flowLogsParser.ParseFlowLogs(flowFogFilePath)

# Write output to respective files
with open("tags_counts.csv", "w") as file:
    file.write("Tag,Count\n")
    for key, value in flowLogsParser.tagsMatchCounts.items():
        if key == "Untagged":
            continue
        entry = f"{key},{value}"
        file.write(entry + "\n")
    if "Untagged" in flowLogsParser.tagsMatchCounts:
        key = "Untagged"
        value = flowLogsParser.tagsMatchCounts["Untagged"]
        entry = f"{key},{value}"
        file.write(entry + "\n")

with open("port_protocol_combination_counts.csv", "w") as file:
    file.write("Port,Protocol,Count\n")
    for key, value in flowLogsParser.portAndProtocolMatchCounts.items():
        entry = f"{key[0]},{key[1]},{value}"
        file.write(entry + "\n")