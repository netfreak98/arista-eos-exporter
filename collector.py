"""Arista metrics collector."""

import logging
import os
import time

from prometheus_client.core import GaugeMetricFamily, InfoMetricFamily

import pyeapi

PORT_STATS_NAMES = [
    "inBroadcastPkts",
    "inDiscards",
    "inMulticastPkts",
    "inOctets",
    "inUcastPkts",
    "outBroadcastPkts",
    "outDiscards",
    "outMulticastPkts",
    "outOctets",
    "outUcastPkts",
]


class AristaMetricsCollector(object):
    """Main class of the collector."""

    def __init__(self, config, target):
        """Initialize the collector."""
        self._username = os.getenv("ARISTA_USERNAME", config["username"])
        self._password = os.getenv("ARISTA_PASSWORD", config["password"])
        self._protocol = config.get("protocol", "https")
        self._timeout = config["timeout"]
        self._target = target
        self._labels = {}
        self._switch_up = 0
        self._responsetime = 0
        self._memtotal = 0
        self._memfree = 0
        self._connection = False
        self._interfaces = False
        self._module_names = config.get("module_names")
        self._scrape_durations = GaugeMetricFamily(
            "arista_scrape_duration_seconds", "Duration of a collector scrape."
        )

    def add_scrape_duration(self, module_name, duration):
        """Add scrape duration metrics."""
        self._scrape_durations.add_sample(
            "arista_scrape_duration_seconds",
            value=duration,
            labels=({"collector": module_name}),
        )

    def get_connection(self):
        """Get the Pyeapi connection object."""
        # set the default timeout
        logging.debug(f"Setting timeout to {self._timeout}")
        if not self._connection:
            logging.info(f"Connecting to switch {self._target}")
            self._connection = pyeapi.connect(
                transport=self._protocol,
                host=self._target,
                username=self._username,
                password=self._password,
                timeout=self._timeout,
            )
            # workaround to allow sslv3 ciphers for python =>3.10
            self._connection.transport._context.set_ciphers("DEFAULT")
        return self._connection

    def switch_command(self, command):
        """Run a switch command."""
        switch_result = ""

        connection = self.get_connection()

        try:
            logging.debug(f"Running command {command}")
            switch_result = connection.execute([command])
        except pyeapi.eapilib.ConnectionError as pyeapi_connect_except:
            self._connection = False
            logging.error(
                ("PYEAPI Client Connection Exception: " f"{pyeapi_connect_except}")
            )
        except pyeapi.eapilib.CommandError as pyeapi_command_except:
            self._connection = False
            logging.error(
                ("PYEAPI Client Command Exception: " f"{pyeapi_command_except}")
            )
        finally:
            return switch_result

    def _get_labels(self):
        """Get Prometheus labels."""
        start = time.time()
        # Get the switch info for the labels
        switch_info = self.switch_command("show version")
        try:
            si_res = switch_info["result"][0]
        except Exception as e:
            logging.debug(f"No result from switch {self._target}: {e}")
            labels_switch = {"model": "unknown", "serial": "unknown"}
            self._switch_up = 0
        else:
            logging.debug(f"Received a result from switch {self._target}")
            labels_switch = {
                "model": si_res["modelName"],
                "serial": si_res["serialNumber"],
                "version": si_res["version"],
            }
            self._memtotal = si_res["memTotal"]
            self._memfree = si_res["memFree"]
            self._switch_up = 1

        end = time.time()
        self._responsetime = end - start
        self.add_scrape_duration("base", self._responsetime)
        self._labels.update(labels_switch)

    def collect_memory(self):
        """Collect memory data."""
        # Export the memory usage data
        yield GaugeMetricFamily(
            "arista_mem_total", "Total memory available", value=self._memtotal
        )
        yield GaugeMetricFamily(
            "arista_mem_free", "Total memory free", value=self._memfree
        )

    def collect_tcam(self):
        """Collect TCAM data."""
        # Get the tcam usage data
        switch_tcam = self.switch_command("show hardware capacity")

        if (
            not switch_tcam
            or "result" not in switch_tcam
            or len(switch_tcam["result"]) == 0
        ):
            return

        used_metrics = GaugeMetricFamily(
            "arista_tcam_used", "TCAM Usage Data", labels=["table", "chip", "feature"]
        )
        total_metrics = GaugeMetricFamily(
            "arista_tcam_total", "TCAM Capacity", labels=["table", "chip", "feature"]
        )

        for entry in switch_tcam["result"][0].get("tables", []):
            try:
                table = entry["table"]
                chip = entry["chip"]
                feature = entry["feature"]
                used = entry["used"]
                max_limit = entry["maxLimit"]

                labels = {"table": table, "chip": chip, "feature": feature}
                logging.debug(f"Adding table={table} value={used} labels={labels}")

                used_metrics.add_sample("arista_tcam_used", value=used, labels=labels)
                total_metrics.add_sample(
                    "arista_tcam_total", value=max_limit, labels=labels
                )
            except KeyError:
                logging.error("KeyError in switch_tcam entries")
                continue

        yield total_metrics
        yield used_metrics

    def collect_port(self):
        """Collect port data."""
        port_interfaces = self.switch_command("show interfaces")
        if (
            not port_interfaces
            or "result" not in port_interfaces
            or len(port_interfaces["result"]) == 0
        ):
            return

        self._interfaces = port_interfaces["result"][0].get("interfaces", {})

        port_stats = {
            k: GaugeMetricFamily(
                f"arista_port_{k}",
                f"Port stats {k}",
                labels=["device", "description", "mac", "mtu"],
            )
            for k in PORT_STATS_NAMES
        }

        port_admin_up = GaugeMetricFamily(
            "arista_admin_up",
            "Value 1 if port is not shutdown",
            labels=["device", "description"],
        )

        port_l2_up = GaugeMetricFamily(
            "arista_l2_up",
            "Value 1 if port is connected",
            labels=["device", "description"],
        )

        port_bandwidth = GaugeMetricFamily(
            "arista_port_bandwidth",
            "Bandwidth in bits/s",
            labels=["device", "description"],
        )

        for interface, iface in self._interfaces.items():
            data = iface.get("interfaceCounters")
            if not data:
                logging.debug(
                    f"Interface {interface} on {self._target} does not have interfaceCounters, skipping"
                )
                continue

            labels = [iface["name"], iface["description"]]

            port_admin_up_value = 1 if iface.get("interfaceStatus") != "disabled" else 0
            port_l2_up_value = 1 if iface.get("lineProtocolStatus") == "up" else 0

            port_admin_up.add_metric(labels=labels, value=port_admin_up_value)
            port_l2_up.add_metric(labels=labels, value=port_l2_up_value)
            port_bandwidth.add_metric(
                labels=labels, value=int(iface.get("bandwidth", 0))
            )

            metric_labels = labels + [iface["physicalAddress"], str(iface["mtu"])]
            for port_stat in PORT_STATS_NAMES:
                port_stats[port_stat].add_metric(
                    metric_labels, float(data.get(port_stat, 0))
                )

        yield from port_stats.values()
        yield port_admin_up
        yield port_l2_up
        yield port_bandwidth

    def collect_transceiver(self):
        """Collect transceiver data."""
        transceiver_data = self.switch_command("show interfaces transceiver detail")
        sensor_entries = ["rxPower", "txBias", "txPower", "voltage"]

        if not transceiver_data:
            return

        transceiver_interfaces = transceiver_data["result"][0].get("interfaces", {})

        transceiver_labels = [
            "device",
            "sensor",
            "mediaType",
            "serial",
            "description",
            "lane",
        ]
        transceiver_stats_metrics = GaugeMetricFamily(
            "arista_transceiver_stats",
            "transceiver Statistics",
            labels=transceiver_labels,
        )

        alarm_labels = ["device", "lane", "sensor", "alarmType"]
        transceiver_alarms = GaugeMetricFamily(
            "arista_transceiver_alarms", "transceiver Alarms", labels=alarm_labels
        )

        for iface, data in transceiver_interfaces.items():
            if not data:
                logging.debug(f"Port does not have transceiver: {iface}")
                continue

            lane = iface
            description = self._interfaces.get(iface, {}).get("description", "")

            # Lane detection.
            if iface not in self._interfaces:
                try_iface = "/".join(iface.split("/")[0:-1]) + "/1"
                if transceiver_interfaces.get(iface, {}).get(
                    "vendorSn"
                ) == transceiver_interfaces.get(try_iface, {}).get("vendorSn"):
                    lane = iface
                    iface = try_iface
                    logging.debug(f"Setting lane {lane} as part of {iface}")

            for sensor in sensor_entries:
                labels = [
                    iface,
                    sensor,
                    data["mediaType"],
                    data["vendorSn"],
                    description,
                    lane,
                ]
                logging.debug(
                    f"Adding: interface={iface} sensor={sensor} value={data[sensor]} labels={labels}"
                )
                transceiver_stats_metrics.add_metric(
                    value=float(data[sensor]), labels=labels
                )

                # Check thresholds and generate alerts
                thresholds = data["details"].get(sensor, {})
                alert_labels = [iface, lane, sensor]

                for alert_type, boundary in [
                    ("highAlarm", "highAlarm"),
                    ("highWarn", "highWarn"),
                    ("lowAlarm", "lowAlarm"),
                    ("lowWarn", "lowWarn"),
                ]:
                    if (
                        alert_type in thresholds
                        and data[sensor] > thresholds[alert_type]
                    ):
                        transceiver_alarms.add_metric(
                            labels=alert_labels + [boundary], value=data[sensor]
                        )

        yield transceiver_stats_metrics
        yield transceiver_alarms

    def collect_bgp(self):
        """Collect BGP data."""
        ipv4_data = self.switch_command("show ip bgp summary vrf all")["result"][0][
            "vrfs"
        ]
        ipv6_data = self.switch_command("show ipv6 bgp summary vrf all")["result"][0][
            "vrfs"
        ]

        prefixes = GaugeMetricFamily(
            "arista_bgp_accepted_prefixes",
            "Number of prefixes accepted",
            labels=["vrf", "peer", "asn"],
        )
        peer_state = InfoMetricFamily(
            "arista_bgp_peer_state",
            "State of the BGP peer",
            labels=["vrf", "peer", "asn", "state", "router_id"],
        )

        def process_bgp_data(bgp_data):
            for vrf, vrf_data in bgp_data.items():
                peers = vrf_data.get("peers", {})
                router_id = vrf_data["routerId"]

                for peer, peer_data in peers.items():
                    labels_info = {
                        "vrf": vrf,
                        "router_id": router_id,
                        "peer": peer,
                        "asn": str(peer_data["asn"]),
                        "state": peer_data["peerState"],
                    }
                    peer_state.add_metric(value=labels_info, labels=labels_info)
                    labels_gauge = [vrf, peer, str(peer_data["asn"])]
                    prefixes.add_metric(
                        value=peer_data["prefixReceived"], labels=labels_gauge
                    )

        process_bgp_data(ipv4_data)
        process_bgp_data(ipv6_data)

        yield peer_state
        yield prefixes

    def collect_power(self):
        """Collect power data."""
        measurements = ["inputCurrent", "inputVoltage", "outputCurrent", "outputPower"]
        data = self.switch_command("show environment power")

        psu_info = InfoMetricFamily(
            "arista_power_supply",
            "State of the power supply",
            labels=["id", "state", "model", "capacity_watts"],
        )
        psu_power = GaugeMetricFamily(
            "arista_power_supply_power",
            "Power supply power measurements",
            labels=["id", "measurement"],
        )
        psu_temp = GaugeMetricFamily(
            "arista_power_supply_temperature",
            "Power supply temperature sensors",
            labels=["id", "status", "sensor"],
        )
        psu_fan = GaugeMetricFamily(
            "arista_power_supply_fan_speed_percent",
            "Power supply fan speed sensors",
            labels=["id", "status", "sensor"],
        )

        if "result" in data and data["result"]:
            for psu_id, psu in data["result"][0].get("powerSupplies", {}).items():
                labels = {
                    "state": psu.get("state", ""),
                    "model": psu.get("modelName", ""),
                    "capacity_watts": str(psu.get("capacity", "")),
                    "id": str(psu_id),
                }

                psu_info.add_metric(value=labels, labels=labels)

                for measurement in measurements:
                    psu_power.add_metric(
                        value=psu.get(measurement, 0), labels=[psu_id, measurement]
                    )

                for name, sensor_data in psu.get("tempSensors", {}).items():
                    psu_temp.add_metric(
                        value=sensor_data.get("temperature", 0),
                        labels=[psu_id, sensor_data.get("status", ""), name],
                    )

                for name, fan_data in psu.get("fans", {}).items():
                    psu_fan.add_metric(
                        value=fan_data.get("speed", 0),
                        labels=[psu_id, fan_data.get("status", ""), name],
                    )

        yield psu_info
        yield psu_power
        yield psu_temp
        yield psu_fan

    def collect_cpu(self):
        """Collect CPU data."""
        data = self.switch_command("show processes top once")

        # Time Info metrics
        time_info = GaugeMetricFamily(
            "arista_time_info", "Time related metrics", labels=["id"]
        )

        # Threads State Info metrics
        threads_state_info = GaugeMetricFamily(
            "arista_threads_state", "Threads state metrics", labels=["id"]
        )

        # CPU Info metrics
        cpu_info = GaugeMetricFamily("arista_cpu", "CPU usage metrics", labels=["type"])

        # Memory Info metrics
        mem_info = GaugeMetricFamily(
            "arista_memory_info",
            "Memory information metrics",
            labels=["type", "metric"],
        )

        # Process Info metrics
        process_info = GaugeMetricFamily(
            "arista_process_info", "Process related metrics", labels=["pid", "metric"]
        )

        result = data.get("result", [{}])[0]

        # Extract Time Info metrics
        for metric in ["currentTime", "upTime", "users"]:
            time_info.add_metric([metric], result["timeInfo"].get(metric, 0))

        # Extract Threads State Info metrics
        for state, value in result["threadsStateInfo"].items():
            threads_state_info.add_metric([state], value)

        # Extract CPU Info metrics
        for ctype, value in result["cpuInfo"]["%Cpu(s)"].items():
            cpu_info.add_metric([ctype], value)

        # Extract Memory Info metrics
        for mem_type in ["physicalMem", "swapMem"]:
            for metric, value in result["memInfo"][mem_type].items():
                mem_info.add_metric([mem_type, metric], value)

        # Extract Process Info metrics
        for pid, pinfo in result["processes"].items():
            for metric in ["cpuPct", "memPct", "activeTime"]:
                process_info.add_metric([pid, metric], pinfo.get(metric, 0))

        yield time_info
        yield threads_state_info
        yield cpu_info
        yield mem_info
        yield process_info

    def get_all_modules(self):
        """Get all supported modules."""
        return {
            "memory": self.collect_memory,
            "tcam": self.collect_tcam,
            "port": self.collect_port,
            "transceiver": self.collect_transceiver,
            "bgp": self.collect_bgp,
            "power": self.collect_power,
            "cpu": self.collect_cpu,
        }

    def get_modules(self):
        """Get modules."""
        all_modules = self.get_all_modules()
        if not self._module_names:
            return all_modules

        modules = self._module_names.split(",")
        module_functions = {
            module: all_modules[module]
            for module in modules
            if module in all_modules or module == "all"
        }

        if "all" in module_functions:
            return all_modules

        missing_modules = set(modules) - set(module_functions.keys())
        for module in missing_modules:
            logging.warning(f"Unknown module requested: {module}. Ignoring")

        return module_functions

    def collect(self):
        """Collect the metrics."""
        self._get_labels()
        self._interfaces = False
        # Export the up and response metrics
        yield GaugeMetricFamily(
            "arista_up",
            (
                "Information whether the switch is reachable "
                "and responds to API calls"
            ),
            value=self._switch_up,
        )

        if self._switch_up == 1:

            yield InfoMetricFamily(
                "arista_hw",
                (
                    "Information about this arista device, "
                    "such as serial number and model"
                ),
                value=self._labels,
            )

            for name, generator in self.get_modules().items():
                start = time.time()
                for metric in generator():
                    yield metric
                end = time.time()
                self.add_scrape_duration(name, end - start)
        yield self._scrape_durations
