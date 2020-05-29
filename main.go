package main

import (
	"bytes"
	"flag"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"errors"
	mp "github.com/mackerelio/go-mackerel-plugin"
)

type FalconPlugin struct {
	Prefix string
}

func (f FalconPlugin) GraphDefinition() map[string]mp.Graphs {
	labelPrefix := strings.Title(f.MetricKeyPrefix())
	return map[string]mp.Graphs{
		"activity": {
			Label: labelPrefix + " Cloud Activity",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "activity_attempts", Label: "Attempts", Diff: false, Stacked: false},
				{Name: "activity_connects", Label: "Connects", Diff: false, Stacked: false},
				{Name: "activity_failures", Label: "Failures", Diff: false, Stacked: false},
				{Name: "activity_timeouts", Label: "Timeouts", Diff: false, Stacked: false},
				{Name: "activity_malformed_messages", Label: "Malformed Messages", Diff: false, Stacked: false},
				{Name: "activity_errors", Label: "Errors", Diff: false, Stacked: false},
			},
		},
		"message_store": {
			Label: labelPrefix + " Message Store",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "message_store_capacity", Label: "Capacity", Diff: false, Stacked: false},
				{Name: "message_store_size", Label: "Size", Diff: false, Stacked: false},
			},
		},
		"event_sums": {
			Label: labelPrefix + " Event Sums",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "event_sums_sent", Label: "Sent", Diff: false, Stacked: false},
				{Name: "event_sums_received", Label: "Received", Diff: false, Stacked: false},
				{Name: "event_sums_ignored", Label: "Ignored", Diff: false, Stacked: false},
				{Name: "event_sums_resent", Label: "Resent", Diff: false, Stacked: false},
				{Name: "event_sums_resend_limit", Label: "Resend Limit", Diff: false, Stacked: false},
				{Name: "event_sums_overflow", Label: "Overflow", Diff: false, Stacked: false},
			},
		},
		"acknowledgement_sums": {
			Label: labelPrefix + " Acknowledgement Sums",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "acknowledgement_sums_sent", Label: "Sent", Diff: false, Stacked: false},
				{Name: "acknowledgement_sums_received", Label: "Received", Diff: false, Stacked: false},
				{Name: "acknowledgement_sums_ignored", Label: "Ignored", Diff: false, Stacked: false},
				{Name: "acknowledgement_sums_resent", Label: "Resent", Diff: false, Stacked: false},
				{Name: "acknowledgement_sums_resend_limit", Label: "Resend Limit", Diff: false, Stacked: false},
				{Name: "acknowledgement_sums_overflow", Label: "Overflow", Diff: false, Stacked: false},
			},
		},
		"events_sent": {
			Label: labelPrefix + " Events Sent",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "agent_connect_mac_v4", Label: "AgentConnectMacV4", Diff: false, Stacked: false},
				{Name: "asep_file_change_mac_v1", Label: "AsepFileChangeMacV1", Diff: false, Stacked: false},
				{Name: "asep_file_change_mac_v2", Label: "AsepFileChangeMacV2", Diff: false, Stacked: false},
				{Name: "associate_tree_id_with_root_mac_v5", Label: "AssociateTreeIdWithRootMacV5", Diff: false, Stacked: false},
				{Name: "b_zip2_file_written_mac_v1", Label: "BZip2FileWrittenMacV1", Diff: false, Stacked: false},
				{Name: "channel_version_required_mac_v1", Label: "ChannelVersionRequiredMacV1", Diff: false, Stacked: false},
				{Name: "config_state_update_mac_v1", Label: "ConfigStateUpdateMacV1", Diff: false, Stacked: false},
				{Name: "critical_file_modified_mac_v2", Label: "CriticalFileModifiedMacV2", Diff: false, Stacked: false},
				{Name: "current_system_tags_mac_v1", Label: "CurrentSystemTagsMacV1", Diff: false, Stacked: false},
				{Name: "directory_create_mac_v1", Label: "DirectoryCreateMacV1", Diff: false, Stacked: false},
				{Name: "dns_request_mac_v1", Label: "DnsRequestMacV1", Diff: false, Stacked: false},
				{Name: "dynamic_classification_mac_v1", Label: "DynamicClassificationMacV1", Diff: false, Stacked: false},
				{Name: "end_of_process_mac_v14", Label: "EndOfProcessMacV14", Diff: false, Stacked: false},
				{Name: "executable_deleted_mac_v1", Label: "ExecutableDeletedMacV1", Diff: false, Stacked: false},
				{Name: "firewall_delete_rule_i_p4_mac_v1", Label: "FirewallDeleteRuleIP4MacV1", Diff: false, Stacked: false},
				{Name: "firewall_delete_rule_i_p6_mac_v1", Label: "FirewallDeleteRuleIP6MacV1", Diff: false, Stacked: false},
				{Name: "firewall_disabled_mac_v1", Label: "FirewallDisabledMacV1", Diff: false, Stacked: false},
				{Name: "firewall_enabled_mac_v1", Label: "FirewallEnabledMacV1", Diff: false, Stacked: false},
				{Name: "firewall_set_rule_i_p4_mac_v1", Label: "FirewallSetRuleIP4MacV1", Diff: false, Stacked: false},
				{Name: "firewall_set_rule_i_p6_mac_v1", Label: "FirewallSetRuleIP6MacV1", Diff: false, Stacked: false},
				{Name: "fs_volume_mounted_mac_v1", Label: "FsVolumeMountedMacV1", Diff: false, Stacked: false},
				{Name: "fs_volume_unmounted_mac_v1", Label: "FsVolumeUnmountedMacV1", Diff: false, Stacked: false},
				{Name: "hash_policy_lightning_query_mac_v2", Label: "HashPolicyLightningQueryMacV2", Diff: false, Stacked: false},
				{Name: "image_hash_mac_v1", Label: "ImageHashMacV1", Diff: false, Stacked: false},
				{Name: "l_f_o_download_confirmation_mac_v1", Label: "LFODownloadConfirmationMacV1", Diff: false, Stacked: false},
				{Name: "lightning_latency_info_mac_v1", Label: "LightningLatencyInfoMacV1", Diff: false, Stacked: false},
				{Name: "local_ip_address_i_p4_mac_v1", Label: "LocalIpAddressIP4MacV1", Diff: false, Stacked: false},
				{Name: "local_ip_address_removed_i_p4_mac_v1", Label: "LocalIpAddressRemovedIP4MacV1", Diff: false, Stacked: false},
				{Name: "mach_o_file_written_mac_v3", Label: "MachOFileWrittenMacV3", Diff: false, Stacked: false},
				{Name: "neighbor_list_i_p4_mac_v1", Label: "NeighborListIP4MacV1", Diff: false, Stacked: false},
				{Name: "network_connect_i_p4_mac_v5", Label: "NetworkConnectIP4MacV5", Diff: false, Stacked: false},
				{Name: "network_connect_i_p6_mac_v5", Label: "NetworkConnectIP6MacV5", Diff: false, Stacked: false},
				{Name: "network_listen_i_p4_mac_v5", Label: "NetworkListenIP4MacV5", Diff: false, Stacked: false},
				{Name: "network_listen_i_p6_mac_v5", Label: "NetworkListenIP6MacV5", Diff: false, Stacked: false},
				{Name: "new_executable_renamed_mac_v1", Label: "NewExecutableRenamedMacV1", Diff: false, Stacked: false},
				{Name: "new_executable_written_mac_v2", Label: "NewExecutableWrittenMacV2", Diff: false, Stacked: false},
				{Name: "new_script_written_mac_v2", Label: "NewScriptWrittenMacV2", Diff: false, Stacked: false},
				{Name: "ole_file_written_mac_v1", Label: "OleFileWrittenMacV1", Diff: false, Stacked: false},
			},
		},
		"events_received": {
			Label: labelPrefix + " Events Received",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "hash_policy_lightning_response_mac_v2", Label: "HashPolicyLightningResponseMacV2", Diff: false, Stacked: false},
				{Name: "l_f_o_download_mac_v1", Label: "LFODownloadMacV1", Diff: false, Stacked: false},
			},
		},
		"communications_bridge": {
			Label: labelPrefix + " Communications Bridge",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "communications_bridge_kernel_sent", Label: "Sent (kerenel)", Diff: false, Stacked: false},
				{Name: "communications_bridge_kernel_received", Label: "Received (kerenel)", Diff: false, Stacked: false},
				{Name: "communications_bridge_user_sent", Label: "Sent (user)", Diff: false, Stacked: false},
				{Name: "communications_bridge_user_received", Label: "Received (user)", Diff: false, Stacked: false},
			},
		},
		"bus_bridge": {
			Label: labelPrefix + " Bus Bridge",
			Unit:  mp.UnitInteger,
			Metrics: []mp.Metrics{
				{Name: "bus_bridge_kernel_sent", Label: "Sent (kerenel)", Diff: false, Stacked: false},
				{Name: "bus_bridge_kernel_received", Label: "Received (kerenel)", Diff: false, Stacked: false},
				{Name: "bus_bridge_user_sent", Label: "Sent (user)", Diff: false, Stacked: false},
				{Name: "bus_bridge_user_received", Label: "Received (user)", Diff: false, Stacked: false},
				{Name: "bus_bridge_queue_size", Label: "Queue Size", Diff: false, Stacked: false},
			},
		},
	}
}

func (f FalconPlugin) FetchMetrics() (map[string]float64, error) {
	stat := map[string]float64{}
	cmd := exec.Command("/Library/CS/falconctl", "stats")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Errorf("falconctl failed.")
		return nil, err
	}

	type FalconOutputFormat struct {
		regex *regexp.Regexp
		index int
	}

	regexmap := map[string]*FalconOutputFormat{
		// Message Store
		"message_store_capacity": &FalconOutputFormat{regexp.MustCompile(" +Capacity: ([0-9]+)"), 0},
		"message_store_size":     &FalconOutputFormat{regexp.MustCompile(" +Size: ([0-9]+)"), 0},

		// Cloud Activity
		"activity_attempts":           &FalconOutputFormat{regexp.MustCompile(" +Attempts: ([0-9]+)"), 0},
		"activity_connects":           &FalconOutputFormat{regexp.MustCompile(" +Connects: ([0-9]+)"), 0},
		"activity_failures":           &FalconOutputFormat{regexp.MustCompile(" +Failures: ([0-9]+)"), 0},
		"activity_timeouts":           &FalconOutputFormat{regexp.MustCompile(" +Timeouts: ([0-9]+)"), 0},
		"activity_malformed_messages": &FalconOutputFormat{regexp.MustCompile(" +Malformed Messages: ([0-9]+)"), 0},
		"activity_errors":             &FalconOutputFormat{regexp.MustCompile(" +Errors: ([0-9]+)"), 0},

		// Event Sums
		"event_sums_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +([0-9]+) "), 0},
		"event_sums_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +([0-9]+) "), 0},
		"event_sums_ignored":      &FalconOutputFormat{regexp.MustCompile(" +Ignored +([0-9]+) "), 0},
		"event_sums_resent":       &FalconOutputFormat{regexp.MustCompile(" +Resent +([0-9]+) "), 0},
		"event_sums_resend_limit": &FalconOutputFormat{regexp.MustCompile(" +Resend Limit +([0-9]+) "), 0},
		"event_sums_overflow":     &FalconOutputFormat{regexp.MustCompile(" +Overflow +([0-9]+) "), 0},

		// Acknowledgement Sums
		"acknowledgement_sums_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +([0-9]+) "), 1},
		"acknowledgement_sums_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +([0-9]+) "), 1},
		"acknowledgement_sums_ignored":      &FalconOutputFormat{regexp.MustCompile(" +Ignored +([0-9]+) "), 1},
		"acknowledgement_sums_resent":       &FalconOutputFormat{regexp.MustCompile(" +Resent +([0-9]+) "), 1},
		"acknowledgement_sums_resend_limit": &FalconOutputFormat{regexp.MustCompile(" +Resend Limit +([0-9]+) "), 1},
		"acknowledgement_sums_overflow":     &FalconOutputFormat{regexp.MustCompile(" +Overflow +([0-9]+) "), 1},

		// Events Sent
		"agent_connect_mac_v4":                 &FalconOutputFormat{regexp.MustCompile(" +AgentConnectMacV4 +([0-9]+) "), 0},
		"asep_file_change_mac_v1":              &FalconOutputFormat{regexp.MustCompile(" +AsepFileChangeMacV1 +([0-9]+) "), 0},
		"asep_file_change_mac_v2":              &FalconOutputFormat{regexp.MustCompile(" +AsepFileChangeMacV2 +([0-9]+) "), 0},
		"associate_tree_id_with_root_mac_v5":   &FalconOutputFormat{regexp.MustCompile(" +AssociateTreeIdWithRootMacV5 +([0-9]+) "), 0},
		"b_zip2_file_written_mac_v1":           &FalconOutputFormat{regexp.MustCompile(" +BZip2FileWrittenMacV1 +([0-9]+) "), 0},
		"channel_version_required_mac_v1":      &FalconOutputFormat{regexp.MustCompile(" +ChannelVersionRequiredMacV1 +([0-9]+) "), 0},
		"config_state_update_mac_v1":           &FalconOutputFormat{regexp.MustCompile(" +ConfigStateUpdateMacV1 +([0-9]+) "), 0},
		"critical_file_modified_mac_v2":        &FalconOutputFormat{regexp.MustCompile(" +CriticalFileModifiedMacV2 +([0-9]+) "), 0},
		"current_system_tags_mac_v1":           &FalconOutputFormat{regexp.MustCompile(" +CurrentSystemTagsMacV1 +([0-9]+) "), 0},
		"directory_create_mac_v1":              &FalconOutputFormat{regexp.MustCompile(" +DirectoryCreateMacV1 +([0-9]+) "), 0},
		"dns_request_mac_v1":                   &FalconOutputFormat{regexp.MustCompile(" +DnsRequestMacV1 +([0-9]+) "), 0},
		"dynamic_classification_mac_v1":        &FalconOutputFormat{regexp.MustCompile(" +DynamicClassificationMacV1 +([0-9]+) "), 0},
		"end_of_process_mac_v14":               &FalconOutputFormat{regexp.MustCompile(" +EndOfProcessMacV14 +([0-9]+) "), 0},
		"executable_deleted_mac_v1":            &FalconOutputFormat{regexp.MustCompile(" +ExecutableDeletedMacV1 +([0-9]+) "), 0},
		"firewall_delete_rule_i_p4_mac_v1":     &FalconOutputFormat{regexp.MustCompile(" +FirewallDeleteRuleIP4MacV1 +([0-9]+) "), 0},
		"firewall_delete_rule_i_p6_mac_v1":     &FalconOutputFormat{regexp.MustCompile(" +FirewallDeleteRuleIP6MacV1 +([0-9]+) "), 0},
		"firewall_disabled_mac_v1":             &FalconOutputFormat{regexp.MustCompile(" +FirewallDisabledMacV1 +([0-9]+) "), 0},
		"firewall_enabled_mac_v1":              &FalconOutputFormat{regexp.MustCompile(" +FirewallEnabledMacV1 +([0-9]+) "), 0},
		"firewall_set_rule_i_p4_mac_v1":        &FalconOutputFormat{regexp.MustCompile(" +FirewallSetRuleIP4MacV1 +([0-9]+) "), 0},
		"firewall_set_rule_i_p6_mac_v1":        &FalconOutputFormat{regexp.MustCompile(" +FirewallSetRuleIP6MacV1 +([0-9]+) "), 0},
		"fs_volume_mounted_mac_v1":             &FalconOutputFormat{regexp.MustCompile(" +FsVolumeMountedMacV1 +([0-9]+) "), 0},
		"fs_volume_unmounted_mac_v1":           &FalconOutputFormat{regexp.MustCompile(" +FsVolumeUnmountedMacV1 +([0-9]+) "), 0},
		"hash_policy_lightning_query_mac_v2":   &FalconOutputFormat{regexp.MustCompile(" +HashPolicyLightningQueryMacV2 +([0-9]+) "), 0},
		"image_hash_mac_v1":                    &FalconOutputFormat{regexp.MustCompile(" +ImageHashMacV1 +([0-9]+) "), 0},
		"l_f_o_download_confirmation_mac_v1":   &FalconOutputFormat{regexp.MustCompile(" +LFODownloadConfirmationMacV1 +([0-9]+) "), 0},
		"lightning_latency_info_mac_v1":        &FalconOutputFormat{regexp.MustCompile(" +LightningLatencyInfoMacV1 +([0-9]+) "), 0},
		"local_ip_address_i_p4_mac_v1":         &FalconOutputFormat{regexp.MustCompile(" +LocalIpAddressIP4MacV1 +([0-9]+) "), 0},
		"local_ip_address_removed_i_p4_mac_v1": &FalconOutputFormat{regexp.MustCompile(" +LocalIpAddressRemovedIP4MacV1 +([0-9]+) "), 0},
		"mach_o_file_written_mac_v3":           &FalconOutputFormat{regexp.MustCompile(" +MachOFileWrittenMacV3 +([0-9]+) "), 0},
		"neighbor_list_i_p4_mac_v1":            &FalconOutputFormat{regexp.MustCompile(" +NeighborListIP4MacV1 +([0-9]+) "), 0},
		"network_connect_i_p4_mac_v5":          &FalconOutputFormat{regexp.MustCompile(" +NetworkConnectIP4MacV5 +([0-9]+) "), 0},
		"network_connect_i_p6_mac_v5":          &FalconOutputFormat{regexp.MustCompile(" +NetworkConnectIP6MacV5 +([0-9]+) "), 0},
		"network_listen_i_p4_mac_v5":           &FalconOutputFormat{regexp.MustCompile(" +NetworkListenIP4MacV5 +([0-9]+) "), 0},
		"network_listen_i_p6_mac_v5":           &FalconOutputFormat{regexp.MustCompile(" +NetworkListenIP6MacV5 +([0-9]+) "), 0},
		"new_executable_renamed_mac_v1":        &FalconOutputFormat{regexp.MustCompile(" +NewExecutableRenamedMacV1 +([0-9]+) "), 0},
		"new_executable_written_mac_v2":        &FalconOutputFormat{regexp.MustCompile(" +NewExecutableWrittenMacV2 +([0-9]+) "), 0},
		"new_script_written_mac_v2":            &FalconOutputFormat{regexp.MustCompile(" +NewScriptWrittenMacV2 +([0-9]+) "), 0},
		"ole_file_written_mac_v1":              &FalconOutputFormat{regexp.MustCompile(" +OleFileWrittenMacV1 +([0-9]+) "), 0},

		// Events Received
		"hash_policy_lightning_response_mac_v2": &FalconOutputFormat{regexp.MustCompile(" +HashPolicyLightningResponseMacV2 +([0-9]+) "), 0},
		"l_f_o_download_mac_v1": &FalconOutputFormat{regexp.MustCompile(" +LFODownloadMacV1 +([0-9]+) "), 0},

		// Communications Bridge
		"communications_bridge_kernel_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +([0-9]+) "), 2},
		"communications_bridge_kernel_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +([0-9]+) "), 2},
		"communications_bridge_user_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +[0-9]+ +([0-9]+) "), 2},
		"communications_bridge_user_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +[0-9]+ +([0-9]+) "), 2},

		// Bus Bridge
		"bus_bridge_kernel_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +([0-9]+) "), 3},
		"bus_bridge_kernel_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +([0-9]+) "), 3},
		"bus_bridge_user_sent":         &FalconOutputFormat{regexp.MustCompile(" +Sent +[0-9]+ +([0-9]+) "), 3},
		"bus_bridge_user_received":     &FalconOutputFormat{regexp.MustCompile(" +Received +[0-9]+ +([0-9]+) "), 3},
		"bus_bridge_queue_size":     &FalconOutputFormat{regexp.MustCompile(" +Event Queue Size +- +([0-9]+) "), 0},
	}
	outStr := out.String()

	for k, v := range regexmap {
		stat[k], err = parseMetrics(outStr, v.regex, v.index)
		if err != nil {
			return nil, err
		}
	}

	return stat, nil
}

func parseMetrics(out string, re *regexp.Regexp, reIndex int) (float64, error) {
	res := re.FindAllStringSubmatch(out, -1)
	if res == nil {
		return 0.0, errors.New("cannot get values")
	}
	val, err := strconv.ParseFloat(res[reIndex][1], 64)
	if err != nil {
		return 0.0, errors.New("cannot get values")
	}

	return val, nil
}

func (f FalconPlugin) MetricKeyPrefix() string {
	return "Falcon"
}

func main() {
	optPrefix := flag.String("metric-key-prefix", "Falcon", "Metric key prefix")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	flag.Parse()

	f := FalconPlugin{
		Prefix: *optPrefix,
	}
	plugin := mp.NewMackerelPlugin(f)
	plugin.Tempfile = *optTempfile
	plugin.Run()
}
