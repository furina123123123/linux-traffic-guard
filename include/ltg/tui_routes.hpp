#pragma once

#include <string>
#include <vector>

namespace linux_traffic_guard {

enum class TuiRouteAction {
    Dashboard,
    OneClickRepair,
    TrafficMenu,
    TrafficMaintenanceMenu,
    SecurityMenu,
    AdvancedMenu,
    RunSetupAssistant,
    DependencyDoctor,
    InstallTraffic,
    TrafficDay,
    TrafficMonth,
    TrafficYear,
    TrafficRealtime,
    RemoveTrafficPorts,
    RemoveTrafficAccounting,
    UfwAnalyzeMenu,
    SecurityOpsMenu,
    Fail2banPanel,
    ReliabilitySelfCheck,
    UfwAnalyze24h,
    UfwAnalyze7d,
    UfwAnalyze28d,
    UfwAnalyzeCustom,
    UfwTraceIp,
    UfwCacheMenu,
    UfwCacheStatus,
    UfwCacheClear,
    FocusedPortInspect,
    ConntrackSnapshot,
    LogSummary,
    ExportReport,
    ServiceControl,
    InstallGeoDatabase,
    RawNftTable,
};

struct TuiRouteItem {
    std::string key;
    std::string title;
    std::string detail;
    bool needsRoot = false;
    TuiRouteAction action = TuiRouteAction::Dashboard;
};

struct TuiMenuDefinition {
    std::string title;
    std::string subtitle;
    std::vector<TuiRouteItem> items;
};

class TuiRouteCallbacks {
public:
    virtual ~TuiRouteCallbacks() = default;

    virtual void routeShowDashboard() = 0;
    virtual void routeOneClickRepair() = 0;
    virtual void routeShowTrafficMenu() = 0;
    virtual void routeShowTrafficMaintenanceMenu() = 0;
    virtual void routeShowSecurityMenu() = 0;
    virtual void routeShowAdvancedMenu() = 0;
    virtual void routeRunSetupAssistant() = 0;
    virtual void routeDependencyDoctor() = 0;
    virtual void routeInstallTraffic() = 0;
    virtual void routeTrafficDay() = 0;
    virtual void routeTrafficMonth() = 0;
    virtual void routeTrafficYear() = 0;
    virtual void routeTrafficRealtime() = 0;
    virtual void routeRemoveTrafficPorts() = 0;
    virtual void routeRemoveTrafficAccounting() = 0;
    virtual void routeShowUfwAnalyzeMenu() = 0;
    virtual void routeShowSecurityOpsMenu() = 0;
    virtual void routeShowFail2banPanel() = 0;
    virtual void routeReliabilitySelfCheck() = 0;
    virtual void routeUfwAnalyze24h() = 0;
    virtual void routeUfwAnalyze7d() = 0;
    virtual void routeUfwAnalyze28d() = 0;
    virtual void routeUfwAnalyzeCustom() = 0;
    virtual void routeUfwTraceIp() = 0;
    virtual void routeShowUfwCacheMenu() = 0;
    virtual void routeUfwCacheStatus() = 0;
    virtual void routeUfwCacheClear() = 0;
    virtual void routeFocusedPortInspect() = 0;
    virtual void routeConntrackSnapshot() = 0;
    virtual void routeLogSummary() = 0;
    virtual void routeExportReport() = 0;
    virtual void routeServiceControl() = 0;
    virtual void routeInstallGeoDatabase() = 0;
    virtual void routeRawNftTable() = 0;
};

void dispatchTuiRoute(TuiRouteAction action, TuiRouteCallbacks &callbacks);

TuiMenuDefinition tuiMainMenuDefinition(const std::string &title);
TuiMenuDefinition tuiSetupAssistantMenuDefinition(const std::string &title);
TuiMenuDefinition tuiTrafficMenuDefinition();
TuiMenuDefinition tuiTrafficMaintenanceMenuDefinition();
TuiMenuDefinition tuiSecurityMenuDefinition();
TuiMenuDefinition tuiAdvancedMenuDefinition();
TuiMenuDefinition tuiUfwAnalyzeMenuDefinition();
TuiMenuDefinition tuiUfwCacheMenuDefinition();

} // namespace linux_traffic_guard
