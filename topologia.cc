/*
 * TFG - Simulacion de redes Zero Trust en entornos de Edge Computing mediante NS-3
 * ---------------------------------------------------------------------------------
 * topologia.cc  ->  BINARIO UNICO para los dos escenarios (--scenario)
 *
 *   --scenario=clasica    arquitectura clasica (confianza implicita, sin PEP/PDP)
 *   --scenario=zerotrust  arquitectura Zero Trust (PEP en el router + PDP)
 *
 * La topologia es IDENTICA en ambos casos. Lo unico que cambia es si se instala
 * la politica Zero Trust en el router. Asi cualquier diferencia en las metricas
 * es atribuible exclusivamente a Zero Trust.
 *
 * Topologia (4 micro-segmentos conectados por un router/gateway central = PEP):
 *   Segmento 0 (clientes) : c0,c1,c2   10.1.0.0/24
 *   Segmento 1 (edge)     : e0,e1,e2   10.1.1.0/24
 *   Segmento 2 (servicios): s0,s1      10.1.2.0/24
 *   Segmento 3 (externo)  : a0         10.1.3.0/24   <- origen del DDoS, aislado
 *
 * Trafico (clasificado por puerto destino):
 *   legitimo (8080): c1,c2 -> s0        autorizado, cross-segment
 *   lateral  (9001): c0    -> e0        movimiento lateral east-west NO autorizado
 *   ddos     (7000): a0    -> s0        inundacion volumetrica UDP
 *
 * Modelado de Zero Trust (solo en --scenario=zerotrust):
 *   - PEP (Policy Enforcement Point) en el router: politica de routing que
 *     inspecciona cada flujo en transito y DESCARTA los denegados.
 *       * micro-segmentacion: deniega trafico east-west al puerto 9001
 *       * autenticacion continua + contexto: deniega flujos del origen que falla
 *         la re-autenticacion (la identidad del atacante a0)
 *   - PDP (Policy Decision Point): la decision permit/deny y su coste se modelan
 *     analiticamente en las columnas signaling_bytes, decision_pdp,
 *     latencia_decision_ms y se suman a energia_j. Son 0/"na" en clasica.
 *
 * Uso:
 *   ./ns3 run "scratch/tfg/topologia --scenario=clasica   --seed=1"
 *   ./ns3 run "scratch/tfg/topologia --scenario=zerotrust --seed=1"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-list-routing.h"
#include "ns3/ipv4-route.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"

#include <fstream>
#include <map>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Topologia");

// ---------------------------------------------------------------------------
// Parametros del experimento
// ---------------------------------------------------------------------------
static const uint16_t PORT_LEGIT   = 8080;
static const uint16_t PORT_IOT     = 8082;  // telemetria IoT (trafico legitimo)
static const uint16_t PORT_LATERAL = 9001;
static const uint16_t PORT_DDOS    = 7000;
static const uint16_t PORT_SCAN    = 22;   // reconocimiento / escaneo de puertos

static const double ATTACK_START = 5.0;
static const double ATTACK_END   = 15.0;

// Modelo energetico: estimacion lineal de primer orden. Las constantes de
// transporte y procesamiento se aplican por igual a ambas arquitecturas, por lo
// que su valor absoluto no afecta a la comparacion relativa entre ellas.
static const double E_BIT  = 1.5e-8;   // J/bit
static const double E_PROC = 5.0e-6;   // J/paquete

// Sobrecarga especifica de Zero Trust (senalizacion de re-autenticacion y coste
// de decision del PDP), modelada de forma explicita y registrada en el CSV.
static const double   REAUTH_INTERVAL = 1.0;   // s entre re-autenticaciones
static const uint32_t REAUTH_BYTES    = 256;   // bytes por intercambio de re-auth
static const double   PDP_DECISION_MS = 1.5;   // latencia de decision del PDP (ms)

// ---------------------------------------------------------------------------
// Politica Zero Trust compartida (PEP y etiquetado del CSV usan la misma regla)
// ---------------------------------------------------------------------------
static Ipv4Address g_attackerIp;

static bool EsDenegado(Ipv4Address src, uint16_t dstPort)
{
    if (dstPort == PORT_LATERAL) return true; // micro-segmentacion east-west
    if (dstPort == PORT_SCAN)    return true; // reconocimiento no autorizado
    if (src == g_attackerIp)     return true; // identidad que falla re-auth
    return false;
}

// ---------------------------------------------------------------------------
// PEP: protocolo de routing que descarta los flujos denegados en el router.
// Se inserta con prioridad alta en el Ipv4ListRouting del router. Si deniega,
// devuelve true (paquete consumido = descartado). Si permite, devuelve false
// para que el global routing existente haga el reenvio normal.
// ---------------------------------------------------------------------------
class ZtPolicyRouting : public Ipv4RoutingProtocol
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::ZtPolicyRouting")
                                .SetParent<Ipv4RoutingProtocol>()
                                .SetGroupName("Internet");
        return tid;
    }

    uint64_t m_dropped = 0;

    static uint16_t DestPort(Ptr<const Packet> p, uint8_t proto)
    {
        if (proto == 6) { TcpHeader t; if (p->PeekHeader(t)) return t.GetDestinationPort(); }
        else if (proto == 17) { UdpHeader u; if (p->PeekHeader(u)) return u.GetDestinationPort(); }
        return 0;
    }

    // Solo policiamos trafico en transito (RouteInput). El trafico originado en
    // el propio router (RouteOutput) no se filtra: devolvemos nullptr para que
    // el siguiente protocolo de la lista lo resuelva.
    Ptr<Ipv4Route> RouteOutput(Ptr<Packet>, const Ipv4Header&, Ptr<NetDevice>,
                               Socket::SocketErrno& sockerr) override
    {
        sockerr = Socket::ERROR_NOTERROR;
        return nullptr;
    }

    bool RouteInput(Ptr<const Packet> p, const Ipv4Header& header, Ptr<const NetDevice>,
                    const UnicastForwardCallback&, const MulticastForwardCallback&,
                    const LocalDeliverCallback&, const ErrorCallback&) override
    {
        uint16_t dport = DestPort(p, header.GetProtocol());
        if (EsDenegado(header.GetSource(), dport)) {
            m_dropped++;
            return true; // descartado por el PEP
        }
        return false;    // permitido -> lo resuelve el global routing
    }

    void NotifyInterfaceUp(uint32_t) override {}
    void NotifyInterfaceDown(uint32_t) override {}
    void NotifyAddAddress(uint32_t, Ipv4InterfaceAddress) override {}
    void NotifyRemoveAddress(uint32_t, Ipv4InterfaceAddress) override {}
    void SetIpv4(Ptr<Ipv4>) override {}
    void PrintRoutingTable(Ptr<OutputStreamWrapper>, Time::Unit) const override {}
};

// ---------------------------------------------------------------------------
// Estado global para el muestreo por ventanas
// ---------------------------------------------------------------------------
struct FlowDelta { uint64_t txBytes=0, rxBytes=0, txPackets=0, rxPackets=0;
                   double delaySum=0, jitterSum=0; };

static std::map<FlowId, FlowDelta>     g_prev;
static std::map<Ipv4Address, uint32_t> g_ipToNode;
static std::map<Ipv4Address, int>      g_ipToSegment;

static Ptr<FlowMonitor>        g_monitor;
static Ptr<Ipv4FlowClassifier> g_classifier;
static std::ofstream           g_csv;
static std::string             g_scenario = "clasica";
static bool                    g_zt       = false;
static uint32_t                g_seed     = 1;
static double                  g_simTime  = 20.0;
static double                  g_window   = 0.5;
static std::string             g_ddosRate = "12Mbps"; // intensidad DDoS (se registra en el CSV)
static uint32_t                g_nClientes = 3;        // numero de clientes (se registra en el CSV)

static std::string TipoTrafico(uint16_t dstPort)
{
    if (dstPort == PORT_LEGIT)   return "legitimo";
    if (dstPort == PORT_IOT)     return "legitimo";
    if (dstPort == PORT_LATERAL) return "lateral";
    if (dstPort == PORT_DDOS)    return "ddos";
    if (dstPort == PORT_SCAN)    return "scan";
    return "otro";
}

static void MuestrearFlujos()
{
    g_monitor->CheckForLostPackets();
    auto stats = g_monitor->GetFlowStats();
    double now = Simulator::Now().GetSeconds();
    double tIni = now - g_window;
    int bajoAtaque = (tIni >= ATTACK_START && tIni < ATTACK_END) ? 1 : 0;

    for (auto& kv : stats)
    {
        FlowId id = kv.first;
        const FlowMonitor::FlowStats& s = kv.second;
        Ipv4FlowClassifier::FiveTuple t = g_classifier->FindFlow(id);

        FlowDelta& p = g_prev[id];
        uint64_t dTxBytes   = s.txBytes   - p.txBytes;
        uint64_t dRxBytes   = s.rxBytes   - p.rxBytes;
        uint64_t dTxPackets = s.txPackets - p.txPackets;
        uint64_t dRxPackets = s.rxPackets - p.rxPackets;
        double   dDelay     = s.delaySum.GetSeconds()  - p.delaySum;
        double   dJitter    = s.jitterSum.GetSeconds() - p.jitterSum;

        p.txBytes=s.txBytes; p.rxBytes=s.rxBytes;
        p.txPackets=s.txPackets; p.rxPackets=s.rxPackets;
        p.delaySum=s.delaySum.GetSeconds(); p.jitterSum=s.jitterSum.GetSeconds();

        if (dTxPackets == 0 && dRxPackets == 0) continue;

        std::string tipo = TipoTrafico(t.destinationPort);
        if (tipo == "otro") continue;

        uint32_t srcId = g_ipToNode.count(t.sourceAddress)      ? g_ipToNode[t.sourceAddress]      : 9999;
        uint32_t dstId = g_ipToNode.count(t.destinationAddress) ? g_ipToNode[t.destinationAddress] : 9999;
        int segSrc = g_ipToSegment.count(t.sourceAddress)      ? g_ipToSegment[t.sourceAddress]      : -1;
        int segDst = g_ipToSegment.count(t.destinationAddress) ? g_ipToSegment[t.destinationAddress] : -1;
        int crossSeg = (segSrc != segDst) ? 1 : 0;

        double latMs   = (dRxPackets > 0) ? (dDelay  / dRxPackets) * 1000.0 : 0.0;
        double jitMs   = (dRxPackets > 0) ? (dJitter / dRxPackets) * 1000.0 : 0.0;
        double thrKbps = (dRxBytes * 8.0 / 1000.0) / g_window;
        double pdr     = (dTxPackets > 0) ? std::min(1.0, (double)dRxPackets / dTxPackets) : 0.0;
        double perdida = 1.0 - pdr;
        std::string proto = (t.protocol == 6) ? "tcp" : (t.protocol == 17 ? "udp" : "otro");
        int esAtaque = (tipo == "lateral" || tipo == "ddos" || tipo == "scan") ? 1 : 0;

        // --- Sobrecarga de Zero Trust (modelada) ---------------------------
        uint32_t signaling = 0;
        std::string decision = "na";
        double latDecision = 0.0;
        if (g_zt) {
            bool denegado = EsDenegado(t.sourceAddress, t.destinationPort);
            decision = denegado ? "deny" : "permit";
            latDecision = PDP_DECISION_MS;                 // el PDP siempre decide
            if (!denegado)                                 // solo las sesiones vivas re-autentican
                signaling = (uint32_t)(REAUTH_BYTES * (g_window / REAUTH_INTERVAL));
        }

        double energia = (dTxBytes + dRxBytes + signaling) * 8.0 * E_BIT
                         + (dTxPackets + dRxPackets) * E_PROC;

        g_csv << std::fixed << std::setprecision(4)
              << tIni << ',' << g_scenario << ',' << g_seed << ',' << id << ','
              << srcId << ',' << dstId << ',' << segSrc << ',' << segDst << ',' << crossSeg << ','
              << tipo << ',' << proto << ','
              << dTxBytes << ',' << dRxBytes << ',' << dTxPackets << ',' << dRxPackets << ','
              << latMs << ',' << jitMs << ',' << thrKbps << ',' << pdr << ',' << perdida << ','
              << signaling << ',' << decision << ',' << latDecision << ','
              << energia << ',' << bajoAtaque << ',' << esAtaque << ','
              << g_ddosRate << ',' << g_nClientes << '\n';
    }

    if (now < g_simTime - 1e-9)
        Simulator::Schedule(Seconds(g_window), &MuestrearFlujos);
}

// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    std::string outFile = "";
    std::string perfil = "generico";
    bool fallos = false;
    std::string ddosRate = "12Mbps";   // intensidad del DDoS (barrido)
    uint32_t nClientes = 3;            // numero de clientes/sensores (escalabilidad)
    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "clasica | zerotrust", g_scenario);
    cmd.AddValue("perfil",   "generico | iot (perfil de trafico legitimo)", perfil);
    cmd.AddValue("fallos",   "true: fallo transitorio de un nodo cliente", fallos);
    cmd.AddValue("ddosRate", "intensidad del DDoS, p.ej. 4Mbps|8Mbps|12Mbps|20Mbps", ddosRate);
    cmd.AddValue("nClientes","numero de clientes/sensores (>=3, c0 es el atacante)", nClientes);
    cmd.AddValue("seed",     "semilla RNG", g_seed);
    cmd.AddValue("simTime",  "duracion (s)", g_simTime);
    cmd.AddValue("window",   "ventana de muestreo (s)", g_window);
    cmd.AddValue("out",      "fichero CSV de salida", outFile);
    cmd.Parse(argc, argv);

    g_zt = (g_scenario == "zerotrust");
    if (nClientes < 3) nClientes = 3;  // c0 atacante + al menos c1,c2 legitimos
    g_ddosRate  = ddosRate;            // se registran en cada fila del CSV
    g_nClientes = nClientes;
    if (outFile.empty()) {
        std::string sufijo = (perfil == "generico") ? "" : ("_" + perfil);
        if (fallos) sufijo += "_fallos";
        // Sufijo SIEMPRE descriptivo: evita colisiones entre barridos y que el
        // glob de recoleccion omita los valores por defecto.
        sufijo += "_ddos" + ddosRate;
        sufijo += "_n" + std::to_string(nClientes);
        outFile = g_scenario + sufijo + "_seed" + std::to_string(g_seed) + ".csv";
    }

    RngSeedManager::SetSeed(12345);
    RngSeedManager::SetRun(g_seed);

    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    jitter->SetAttribute("Min", DoubleValue(0.0));
    jitter->SetAttribute("Max", DoubleValue(0.5));

    // -- Nodos --------------------------------------------------------------
    Ptr<Node> router = CreateObject<Node>();
    NodeContainer clientes; clientes.Create(nClientes); // c0 (atacante) + c1..c(n-1)
    NodeContainer edge;     edge.Create(3);     // e0,e1,e2
    NodeContainer serv;     serv.Create(2);     // s0,s1
    NodeContainer ext;      ext.Create(1);      // a0 (atacante, aislado)

    NodeContainer seg0(router); seg0.Add(clientes);
    NodeContainer seg1(router); seg1.Add(edge);
    NodeContainer seg2(router); seg2.Add(serv);
    NodeContainer seg3(router); seg3.Add(ext);

    // -- Enlaces CSMA (enlace edge realista de 10 Mbps) ---------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));

    NetDeviceContainer d0 = csma.Install(seg0);
    NetDeviceContainer d1 = csma.Install(seg1);
    NetDeviceContainer d2 = csma.Install(seg2);
    NetDeviceContainer d3 = csma.Install(seg3);

    // -- Pila IP ------------------------------------------------------------
    InternetStackHelper stack;
    stack.Install(router);
    stack.Install(clientes);
    stack.Install(edge);
    stack.Install(serv);
    stack.Install(ext);

    Ipv4AddressHelper addr;
    addr.SetBase("10.1.0.0", "255.255.255.0"); Ipv4InterfaceContainer i0 = addr.Assign(d0);
    addr.SetBase("10.1.1.0", "255.255.255.0"); Ipv4InterfaceContainer i1 = addr.Assign(d1);
    addr.SetBase("10.1.2.0", "255.255.255.0"); Ipv4InterfaceContainer i2 = addr.Assign(d2);
    addr.SetBase("10.1.3.0", "255.255.255.0"); Ipv4InterfaceContainer i3 = addr.Assign(d3);

    auto registrar = [&](NetDeviceContainer& devs, Ipv4InterfaceContainer& ifs, int seg) {
        for (uint32_t k = 0; k < devs.GetN(); ++k) {
            uint32_t nodeId = devs.Get(k)->GetNode()->GetId();
            Ipv4Address a   = ifs.GetAddress(k);
            g_ipToNode[a]    = nodeId;
            g_ipToSegment[a] = seg;
        }
    };
    registrar(d0, i0, 0);
    registrar(d1, i1, 1);
    registrar(d2, i2, 2);
    registrar(d3, i3, 3);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Direcciones de interes
    Ipv4Address ipServidor = i2.GetAddress(1); // s0
    Ipv4Address ipEdge0    = i1.GetAddress(1); // e0
    g_attackerIp           = i3.GetAddress(1); // a0

    // -- PEP: instalar la politica Zero Trust en el router ------------------
    if (g_zt) {
        Ptr<Ipv4> ipv4router = router->GetObject<Ipv4>();
        Ptr<Ipv4ListRouting> lista = DynamicCast<Ipv4ListRouting>(ipv4router->GetRoutingProtocol());
        Ptr<ZtPolicyRouting> pep = CreateObject<ZtPolicyRouting>();
        lista->AddRoutingProtocol(pep, 100); // prioridad alta: se consulta primero
    }

    // -- Aplicaciones -------------------------------------------------------
    PacketSinkHelper sinkLegit("ns3::TcpSocketFactory",
                               InetSocketAddress(Ipv4Address::GetAny(), PORT_LEGIT));
    PacketSinkHelper sinkLateral("ns3::TcpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), PORT_LATERAL));
    PacketSinkHelper sinkDdos("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), PORT_DDOS));
    PacketSinkHelper sinkScan("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), PORT_SCAN));
    PacketSinkHelper sinkIot("ns3::UdpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), PORT_IOT));
    ApplicationContainer sinks;
    sinks.Add(sinkLegit.Install(serv.Get(0)));
    sinks.Add(sinkLateral.Install(edge.Get(0)));
    sinks.Add(sinkDdos.Install(serv.Get(0)));
    sinks.Add(sinkScan.Install(serv.Get(0)));
    sinks.Add(sinkScan.Install(serv.Get(1)));
    sinks.Add(sinkIot.Install(serv.Get(0)));
    sinks.Start(Seconds(0.5));
    sinks.Stop(Seconds(g_simTime));

    // Legitimo. Dos perfiles seleccionables con --perfil:
    //   generico: c1,c2 -> s0 TCP rafagueado (servicio de aplicacion clasico)
    //   iot     : varios sensores -> s0 UDP, paquetes pequenos periodicos (telemetria Edge)
    if (perfil == "iot") {
        // Sensores en clientes y nodos de borde que emiten telemetria periodica.
        std::vector<Ptr<Node>> sensores = {
            clientes.Get(1), clientes.Get(2), edge.Get(1), edge.Get(2)
        };
        OnOffHelper iot("ns3::UdpSocketFactory", InetSocketAddress(ipServidor, PORT_IOT));
        iot.SetAttribute("DataRate",   StringValue("40kbps"));   // baja tasa
        iot.SetAttribute("PacketSize", UintegerValue(128));      // paquetes pequenos
        // Patron periodico: rafaga corta y silencio, emulando un sensor que reporta.
        iot.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=0.05]"));
        iot.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.45]"));
        for (Ptr<Node> s : sensores) {
            ApplicationContainer a = iot.Install(s);
            a.Start(Seconds(1.0 + jitter->GetValue())); a.Stop(Seconds(g_simTime));
        }
    } else {
        OnOffHelper legit("ns3::TcpSocketFactory", InetSocketAddress(ipServidor, PORT_LEGIT));
        legit.SetAttribute("DataRate", StringValue("2Mbps"));
        legit.SetAttribute("PacketSize", UintegerValue(1024));
        legit.SetAttribute("OnTime",  StringValue("ns3::ExponentialRandomVariable[Mean=0.5]"));
        legit.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.2]"));
        for (uint32_t c = 1; c < nClientes; ++c) {
            ApplicationContainer a = legit.Install(clientes.Get(c));
            a.Start(Seconds(1.0 + jitter->GetValue())); a.Stop(Seconds(g_simTime));
        }
    }

    // Movimiento lateral: c0 -> e0 (TCP, east-west no autorizado)
    OnOffHelper lateral("ns3::TcpSocketFactory", InetSocketAddress(ipEdge0, PORT_LATERAL));
    lateral.SetAttribute("DataRate", StringValue("1Mbps"));
    lateral.SetAttribute("PacketSize", UintegerValue(512));
    lateral.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    lateral.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    {
        ApplicationContainer a = lateral.Install(clientes.Get(0));
        a.Start(Seconds(6.0 + jitter->GetValue())); a.Stop(Seconds(12.0));
    }

    // DDoS volumetrico: a0 (externo) -> s0 (UDP, supera la capacidad del enlace)
    OnOffHelper ddos("ns3::UdpSocketFactory", InetSocketAddress(ipServidor, PORT_DDOS));
    ddos.SetAttribute("DataRate", StringValue(ddosRate));
    ddos.SetAttribute("PacketSize", UintegerValue(512));
    ddos.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    ddos.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    {
        ApplicationContainer a = ddos.Install(ext.Get(0));
        a.Start(Seconds(ATTACK_START)); a.Stop(Seconds(ATTACK_END));
    }

    // Escaneo / reconocimiento: c0 (comprometido) sondea los servidores en el
    // puerto de escaneo. Baja tasa y paquetes pequenos: firma sigilosa, distinta
    // de la inundacion volumetrica. Modela de forma simplificada un reconocimiento.
    for (uint32_t sv = 0; sv < 2; ++sv) {
        OnOffHelper scan("ns3::TcpSocketFactory",
                         InetSocketAddress(i2.GetAddress(sv + 1), PORT_SCAN));
        scan.SetAttribute("DataRate", StringValue("100kbps"));
        scan.SetAttribute("PacketSize", UintegerValue(64));
        scan.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        scan.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer a = scan.Install(clientes.Get(0));
        a.Start(Seconds(6.0 + jitter->GetValue())); a.Stop(Seconds(10.0));
    }

    // -- FlowMonitor + CSV --------------------------------------------------
    FlowMonitorHelper fmHelper;
    g_monitor = fmHelper.InstallAll();
    g_classifier = DynamicCast<Ipv4FlowClassifier>(fmHelper.GetClassifier());

    g_csv.open(outFile);
    g_csv << "timestamp,escenario,seed,flujo_id,src_id,dst_id,segmento_src,segmento_dst,"
          << "cross_segment,tipo_trafico,protocolo,bytes_tx,bytes_rx,paquetes_tx,paquetes_rx,"
          << "latencia_ms,jitter_ms,throughput_kbps,pdr,perdida,signaling_bytes,decision_pdp,"
          << "latencia_decision_ms,energia_j,bajo_ataque,es_ataque,ddos_rate,n_clientes\n";

    // Fallo transitorio de nodo: el cliente c1 cae entre t=8s y t=11s y se
    // recupera, emulando el reinicio o la desconexion de un nodo de borde.
    if (fallos) {
        Ptr<Ipv4> ipC1 = clientes.Get(1)->GetObject<Ipv4>();
        Simulator::Schedule(Seconds(8.0),  &Ipv4::SetDown, ipC1, 1);
        Simulator::Schedule(Seconds(11.0), &Ipv4::SetUp,   ipC1, 1);
    }

    Simulator::Schedule(Seconds(g_window), &MuestrearFlujos);
    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();
    g_csv.close();

    std::cout << "OK -> " << outFile << " (escenario=" << g_scenario
              << ", seed=" << g_seed << ")\n";
    return 0;
}
