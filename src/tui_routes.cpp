#include "ltg/tui_routes.hpp"

namespace linux_traffic_guard {

TuiMenuDefinition tuiMainMenuDefinition(const std::string &title) {
    return {title,
            "按用户目标组织：观察、修复、流量、安全；底层细节收进安全中心。",
            {{"1", "仪表盘", "最快入口，最近31天端口流量和下一步建议", false, TuiRouteAction::Dashboard},
             {"2", "一键修复", "自动补齐依赖、防护策略和流量采样链路", true, TuiRouteAction::OneClickRepair},
             {"3", "流量统计", "开启/追加端口，查看日/月/年流量", false, TuiRouteAction::TrafficMenu},
             {"4", "安全中心", "威胁分析、fail2ban、UFW、可靠性和诊断", false, TuiRouteAction::SecurityMenu}}};
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
            "端口级 vnStat：按日/月/年看端口，并下钻 IP",
            {{"1", "开启/追加端口", "默认追加，不清空已有统计", true, TuiRouteAction::InstallTraffic},
             {"2", "日流量", "端口级 vnStat -d，带 IP 明细入口", false, TuiRouteAction::TrafficDay},
             {"3", "月流量", "端口级 vnStat -m，带 IP 明细入口", false, TuiRouteAction::TrafficMonth},
             {"4", "年流量", "端口级 vnStat -y，带 IP 明细入口", false, TuiRouteAction::TrafficYear},
             {"5", "实时明细", "较慢，读取底层实时计数和 IP 明细", false, TuiRouteAction::TrafficRealtime},
             {"6", "删除统计端口", "停止统计指定端口，保留历史", true, TuiRouteAction::RemoveTrafficPorts},
             {"7", "高级：删除全部统计规则", "高风险，删除底层统计规则", true,
              TuiRouteAction::RemoveTrafficAccounting}}};
}

TuiMenuDefinition tuiSecurityMenuDefinition() {
    return {"安全中心",
            "先看总览，再分析来源；需要改系统时走处置或策略",
            {{"1", "安全总览", "一屏看服务、策略、封禁和下一步", false, TuiRouteAction::SecurityStatus},
             {"2", "分析追查", "来源 Top、端口扫描、IP 下钻、缓存", false, TuiRouteAction::UfwAnalyzeMenu},
             {"3", "处置修复", "封禁/解封、端口规则、核验、同步", true, TuiRouteAction::SecurityOpsMenu},
             {"4", "策略管理", "SSH 防护、扫描升级、白名单", true, TuiRouteAction::Fail2banPanel},
             {"5", "可靠性自检", "验证依赖、更新、防护、统计、诊断是否真落地", true,
              TuiRouteAction::ReliabilitySelfCheck},
             {"6", "高级/诊断", "日志、依赖、导出、conntrack 和底层规则", false, TuiRouteAction::AdvancedMenu}}};
}

TuiMenuDefinition tuiAdvancedMenuDefinition() {
    return {"高级/诊断",
            "日常路径之外的底层排障、日志、依赖和导出",
            {{"1", "依赖检查/修复", "发现缺失后可直接补齐", false, TuiRouteAction::DependencyDoctor},
             {"2", "端口下钻", "监听、防火墙、计数、conntrack", false, TuiRouteAction::FocusedPortInspect},
             {"3", "conntrack 快照", "当前活跃连接视图", false, TuiRouteAction::ConntrackSnapshot},
             {"4", "日志摘要", "fail2ban 与 UFW 日志", false, TuiRouteAction::LogSummary},
             {"5", "导出报告", "写入 /tmp 报告", false, TuiRouteAction::ExportReport},
             {"6", "服务控制", "fail2ban 与 UFW 服务动作", true, TuiRouteAction::ServiceControl},
             {"7", "安装/更新 IP 国家库", "DB-IP Lite 免费 MMDB，用于来源国家展示", true,
              TuiRouteAction::InstallGeoDatabase},
             {"8", "底层计数规则", "查看 nftables 原始输出", false, TuiRouteAction::RawNftTable}}};
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
