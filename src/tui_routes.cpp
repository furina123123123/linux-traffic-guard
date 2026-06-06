#include "ltg/tui_routes.hpp"

namespace linux_traffic_guard {

TuiMenuDefinition tuiMainMenuDefinition(const std::string &title) {
    return {title,
            "按日常目标组织：先看状态，需要时一键修复，再进入流量或安全。",
            {{"1", "仪表盘", "最快入口：最近31天端口流量、安全摘要和下一步建议", false, TuiRouteAction::Dashboard},
             {"2", "一键修复", "自动补齐依赖、防护策略、流量采样，并做验收", true, TuiRouteAction::OneClickRepair},
             {"3", "流量统计", "添加端口，查看端口级日/月/年流量，再下钻 IP", false, TuiRouteAction::TrafficMenu},
             {"4", "安全中心", "威胁分析、处置、fail2ban/UFW 状态和维护", false, TuiRouteAction::SecurityMenu}}};
}

TuiMenuDefinition tuiSetupAssistantMenuDefinition(const std::string &title) {
    return {title,
            "检测到首次/未就绪环境。建议先一键初始化，后续日常使用会直接进入仪表盘。",
            {{"1", "一键初始化/修复", "自动安装缺失依赖、配置并验收两条 fail2ban 防护策略", true,
              TuiRouteAction::RunSetupAssistant},
             {"2", "先看仪表盘", "跳过初始化，只查看已有流量和缓存摘要", false, TuiRouteAction::Dashboard},
             {"3", "依赖检查/修复", "发现缺失后可直接补齐", false, TuiRouteAction::DependencyDoctor}}};
}

TuiMenuDefinition tuiTrafficMenuDefinition() {
    return {"流量统计",
            "日常只需要三步：添加端口、看周期流量、必要时查实时 IP。",
            {{"1", "添加统计端口", "默认追加，不清空已有统计", true, TuiRouteAction::InstallTraffic},
             {"2", "查看日/月/年流量", "端口级 vnStat，支持滚动窗口和指定周期", false, TuiRouteAction::TrafficPeriodMenu},
             {"3", "实时 IP 明细", "较慢，读取底层实时计数，用于排障", false, TuiRouteAction::TrafficRealtime},
             {"4", "统计维护", "停止端口、重置规则、查看底层计数", true, TuiRouteAction::TrafficMaintenanceMenu}}};
}

TuiMenuDefinition tuiTrafficPeriodMenuDefinition() {
    return {"查看流量",
            "像 vnStat 一样先选周期；每个周期里再选择滚动窗口或指定日期。",
            {{"1", "日流量", "端口级 vnStat -d，并保留 IP 明细下钻能力", false, TuiRouteAction::TrafficDay},
             {"2", "月流量", "端口级 vnStat -m，并保留 IP 明细下钻能力", false, TuiRouteAction::TrafficMonth},
             {"3", "年流量", "端口级 vnStat -y，并保留 IP 明细下钻能力", false, TuiRouteAction::TrafficYear}}};
}

TuiMenuDefinition tuiTrafficMaintenanceMenuDefinition() {
    return {"统计维护",
            "低频维护动作集中在这里；普通添加端口不会清空历史数据。",
            {{"1", "停止统计端口", "从统计端口集合移除，保留历史数据", true, TuiRouteAction::RemoveTrafficPorts},
             {"2", "重置底层规则", "高风险，删除底层统计规则并清空实时计数", true, TuiRouteAction::RemoveTrafficAccounting},
             {"3", "查看底层计数规则", "nftables 原始输出，只用于排障", false, TuiRouteAction::RawNftTable}}};
}

TuiMenuDefinition tuiSecurityMenuDefinition() {
    return {"安全中心",
            "先看结论；要改变系统就处置；参数、可靠性和底层工具放进维护。",
            {{"1", "安全总览", "一屏看服务、策略、封禁和下一步", false, TuiRouteAction::SecurityStatus},
             {"2", "威胁分析", "UFW 来源、端口扫描、IP 追查和缓存", false, TuiRouteAction::UfwAnalyzeMenu},
             {"3", "处置 IP/端口", "封禁/解封、端口规则、同步和一致性核验", true, TuiRouteAction::SecurityOpsMenu},
             {"4", "安全维护", "策略参数、可靠性、日志、导出、服务和底层规则", false, TuiRouteAction::AdvancedMenu}}};
}

TuiMenuDefinition tuiAdvancedMenuDefinition() {
    return {"高级维护",
            "日常路径之外的参数、验收、日志、导出和底层排障。",
            {{"1", "策略参数", "SSH 防护、扫描升级、白名单和自定义 jail", true, TuiRouteAction::Fail2banPanel},
             {"2", "可靠性自检", "验证依赖、更新、防护、统计、诊断是否真落地", true,
              TuiRouteAction::ReliabilitySelfCheck},
             {"3", "依赖检查/修复", "发现缺失后可直接补齐", false, TuiRouteAction::DependencyDoctor},
             {"4", "端口下钻", "监听、防火墙、计数、conntrack", false, TuiRouteAction::FocusedPortInspect},
             {"5", "日志摘要", "fail2ban 与 UFW 日志", false, TuiRouteAction::LogSummary},
             {"6", "导出报告", "写入 /tmp 报告", false, TuiRouteAction::ExportReport},
             {"7", "服务控制", "fail2ban 与 UFW 服务动作", true, TuiRouteAction::ServiceControl},
             {"8", "安装/更新 IP 国家库", "DB-IP Lite 免费 MMDB，用于来源国家展示", true,
              TuiRouteAction::InstallGeoDatabase},
             {"9", "conntrack 快照", "当前活跃连接视图", false, TuiRouteAction::ConntrackSnapshot},
             {"10", "底层计数规则", "查看 nftables 原始输出", false, TuiRouteAction::RawNftTable}}};
}

TuiMenuDefinition tuiUfwAnalyzeMenuDefinition() {
    return {"威胁分析",
            "攻击来源、端口扫描和本机监听进程",
            {{"1", "最近24小时", "分析最近 24 小时 UFW 日志", false, TuiRouteAction::UfwAnalyze24h},
             {"2", "最近7天", "分析最近 7 天 UFW 日志", false, TuiRouteAction::UfwAnalyze7d},
             {"3", "最近28天", "分析最近 28 天 UFW 日志", false, TuiRouteAction::UfwAnalyze28d},
             {"4", "自定义时间段", "输入开始/结束日期", false, TuiRouteAction::UfwAnalyzeCustom},
             {"5", "指定IP追查", "先选时间段再输入 IP", false, TuiRouteAction::UfwTraceIp},
             {"6", "分析缓存", "查看缓存状态或手动清理", false, TuiRouteAction::UfwCacheMenu}}};
}

TuiMenuDefinition tuiUfwCacheMenuDefinition() {
    return {"分析缓存",
            "缓存只用于加速威胁分析，不参与防火墙决策",
            {{"1", "缓存状态", "命中范围、行数、最近活跃时间", false, TuiRouteAction::UfwCacheStatus},
             {"2", "清理缓存", "删除 UFW 分析缓存，下次重新解析", true, TuiRouteAction::UfwCacheClear}}};
}

void dispatchTuiRoute(TuiRouteAction action, TuiRouteCallbacks &callbacks) {
    switch (action) {
    case TuiRouteAction::Dashboard:
        callbacks.routeShowDashboard();
        break;
    case TuiRouteAction::OneClickRepair:
        callbacks.routeOneClickRepair();
        break;
    case TuiRouteAction::TrafficMenu:
        callbacks.routeShowTrafficMenu();
        break;
    case TuiRouteAction::TrafficPeriodMenu:
        callbacks.routeShowTrafficPeriodMenu();
        break;
    case TuiRouteAction::TrafficMaintenanceMenu:
        callbacks.routeShowTrafficMaintenanceMenu();
        break;
    case TuiRouteAction::SecurityMenu:
        callbacks.routeShowSecurityMenu();
        break;
    case TuiRouteAction::AdvancedMenu:
        callbacks.routeShowAdvancedMenu();
        break;
    case TuiRouteAction::RunSetupAssistant:
        callbacks.routeRunSetupAssistant();
        break;
    case TuiRouteAction::DependencyDoctor:
        callbacks.routeDependencyDoctor();
        break;
    case TuiRouteAction::InstallTraffic:
        callbacks.routeInstallTraffic();
        break;
    case TuiRouteAction::TrafficDay:
        callbacks.routeTrafficDay();
        break;
    case TuiRouteAction::TrafficMonth:
        callbacks.routeTrafficMonth();
        break;
    case TuiRouteAction::TrafficYear:
        callbacks.routeTrafficYear();
        break;
    case TuiRouteAction::TrafficRealtime:
        callbacks.routeTrafficRealtime();
        break;
    case TuiRouteAction::RemoveTrafficPorts:
        callbacks.routeRemoveTrafficPorts();
        break;
    case TuiRouteAction::RemoveTrafficAccounting:
        callbacks.routeRemoveTrafficAccounting();
        break;
    case TuiRouteAction::SecurityStatus:
        callbacks.routeSecurityStatus();
        break;
    case TuiRouteAction::UfwAnalyzeMenu:
        callbacks.routeShowUfwAnalyzeMenu();
        break;
    case TuiRouteAction::SecurityOpsMenu:
        callbacks.routeShowSecurityOpsMenu();
        break;
    case TuiRouteAction::Fail2banPanel:
        callbacks.routeShowFail2banPanel();
        break;
    case TuiRouteAction::ReliabilitySelfCheck:
        callbacks.routeReliabilitySelfCheck();
        break;
    case TuiRouteAction::UfwAnalyze24h:
        callbacks.routeUfwAnalyze24h();
        break;
    case TuiRouteAction::UfwAnalyze7d:
        callbacks.routeUfwAnalyze7d();
        break;
    case TuiRouteAction::UfwAnalyze28d:
        callbacks.routeUfwAnalyze28d();
        break;
    case TuiRouteAction::UfwAnalyzeCustom:
        callbacks.routeUfwAnalyzeCustom();
        break;
    case TuiRouteAction::UfwTraceIp:
        callbacks.routeUfwTraceIp();
        break;
    case TuiRouteAction::UfwCacheMenu:
        callbacks.routeShowUfwCacheMenu();
        break;
    case TuiRouteAction::UfwCacheStatus:
        callbacks.routeUfwCacheStatus();
        break;
    case TuiRouteAction::UfwCacheClear:
        callbacks.routeUfwCacheClear();
        break;
    case TuiRouteAction::FocusedPortInspect:
        callbacks.routeFocusedPortInspect();
        break;
    case TuiRouteAction::ConntrackSnapshot:
        callbacks.routeConntrackSnapshot();
        break;
    case TuiRouteAction::LogSummary:
        callbacks.routeLogSummary();
        break;
    case TuiRouteAction::ExportReport:
        callbacks.routeExportReport();
        break;
    case TuiRouteAction::ServiceControl:
        callbacks.routeServiceControl();
        break;
    case TuiRouteAction::InstallGeoDatabase:
        callbacks.routeInstallGeoDatabase();
        break;
    case TuiRouteAction::RawNftTable:
        callbacks.routeRawNftTable();
        break;
    }
}

} // namespace linux_traffic_guard
