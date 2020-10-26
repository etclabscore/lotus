package common

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/jsonschema"
	go_openrpc_reflect "github.com/etclabscore/go-openrpc-reflect"
	"github.com/filecoin-project/lotus/api/apistruct"
	logging "github.com/ipfs/go-log/v2"
	meta_schema "github.com/open-rpc/meta-schema"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/libp2p/go-libp2p-core/host"
	metrics "github.com/libp2p/go-libp2p-core/metrics"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	protocol "github.com/libp2p/go-libp2p-core/protocol"
	swarm "github.com/libp2p/go-libp2p-swarm"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/fx"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-jsonrpc/auth"

	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/node/modules/dtypes"
	"github.com/filecoin-project/lotus/node/modules/lp2p"
)

type CommonAPI struct {
	fx.In

	APISecret    *dtypes.APIAlg
	RawHost      lp2p.RawHost
	Host         host.Host
	Router       lp2p.BaseIpfsRouting
	Reporter     metrics.Reporter
	Sk           *dtypes.ScoreKeeper
	ShutdownChan dtypes.ShutdownChan
}

type jwtPayload struct {
	Allow []auth.Permission
}

func (a *CommonAPI) AuthVerify(ctx context.Context, token string) ([]auth.Permission, error) {
	var payload jwtPayload
	if _, err := jwt.Verify([]byte(token), (*jwt.HMACSHA)(a.APISecret), &payload); err != nil {
		return nil, xerrors.Errorf("JWT Verification failed: %w", err)
	}

	return payload.Allow, nil
}

func (a *CommonAPI) AuthNew(ctx context.Context, perms []auth.Permission) ([]byte, error) {
	p := jwtPayload{
		Allow: perms, // TODO: consider checking validity
	}

	return jwt.Sign(&p, (*jwt.HMACSHA)(a.APISecret))
}

func (a *CommonAPI) NetConnectedness(ctx context.Context, pid peer.ID) (network.Connectedness, error) {
	return a.Host.Network().Connectedness(pid), nil
}
func (a *CommonAPI) NetPubsubScores(context.Context) ([]api.PubsubScore, error) {
	scores := a.Sk.Get()
	out := make([]api.PubsubScore, len(scores))
	i := 0
	for k, v := range scores {
		out[i] = api.PubsubScore{ID: k, Score: v}
		i++
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(string(out[i].ID), string(out[j].ID)) > 0
	})

	return out, nil
}

func (a *CommonAPI) NetPeers(context.Context) ([]peer.AddrInfo, error) {
	conns := a.Host.Network().Conns()
	out := make([]peer.AddrInfo, len(conns))

	for i, conn := range conns {
		out[i] = peer.AddrInfo{
			ID: conn.RemotePeer(),
			Addrs: []ma.Multiaddr{
				conn.RemoteMultiaddr(),
			},
		}
	}

	return out, nil
}

func (a *CommonAPI) NetConnect(ctx context.Context, p peer.AddrInfo) error {
	if swrm, ok := a.Host.Network().(*swarm.Swarm); ok {
		swrm.Backoff().Clear(p.ID)
	}

	return a.Host.Connect(ctx, p)
}

func (a *CommonAPI) NetAddrsListen(context.Context) (peer.AddrInfo, error) {
	return peer.AddrInfo{
		ID:    a.Host.ID(),
		Addrs: a.Host.Addrs(),
	}, nil
}

func (a *CommonAPI) NetDisconnect(ctx context.Context, p peer.ID) error {
	return a.Host.Network().ClosePeer(p)
}

func (a *CommonAPI) NetFindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	return a.Router.FindPeer(ctx, p)
}

func (a *CommonAPI) NetAutoNatStatus(ctx context.Context) (i api.NatInfo, err error) {
	autonat := a.RawHost.(*basichost.BasicHost).AutoNat

	if autonat == nil {
		return api.NatInfo{
			Reachability: network.ReachabilityUnknown,
		}, nil
	}

	var maddr string
	if autonat.Status() == network.ReachabilityPublic {
		pa, err := autonat.PublicAddr()
		if err != nil {
			return api.NatInfo{}, err
		}
		maddr = pa.String()
	}

	return api.NatInfo{
		Reachability: autonat.Status(),
		PublicAddr:   maddr,
	}, nil
}

func (a *CommonAPI) NetAgentVersion(ctx context.Context, p peer.ID) (string, error) {
	ag, err := a.Host.Peerstore().Get(p, "AgentVersion")
	if err != nil {
		return "", err
	}

	if ag == nil {
		return "unknown", nil
	}

	return ag.(string), nil
}

func (a *CommonAPI) NetBandwidthStats(ctx context.Context) (metrics.Stats, error) {
	return a.Reporter.GetBandwidthTotals(), nil
}

func (a *CommonAPI) NetBandwidthStatsByPeer(ctx context.Context) (map[string]metrics.Stats, error) {
	out := make(map[string]metrics.Stats)
	for p, s := range a.Reporter.GetBandwidthByPeer() {
		out[p.String()] = s
	}
	return out, nil
}

func (a *CommonAPI) NetBandwidthStatsByProtocol(ctx context.Context) (map[protocol.ID]metrics.Stats, error) {
	return a.Reporter.GetBandwidthByProtocol(), nil
}

func (a *CommonAPI) ID(context.Context) (peer.ID, error) {
	return a.Host.ID(), nil
}

func (a *CommonAPI) Version(context.Context) (api.Version, error) {
	v, err := build.VersionForType(build.RunningNodeType)
	if err != nil {
		return api.Version{}, err
	}

	return api.Version{
		Version:    build.UserVersion(),
		APIVersion: v,

		BlockDelay: build.BlockDelaySecs,
	}, nil
}

func (a *CommonAPI) LogList(context.Context) ([]string, error) {
	return logging.GetSubsystems(), nil
}

func (a *CommonAPI) LogSetLevel(ctx context.Context, subsystem, level string) error {
	return logging.SetLogLevel(subsystem, level)
}

func (a *CommonAPI) Shutdown(ctx context.Context) error {
	a.ShutdownChan <- struct{}{}
	return nil
}

func (a *CommonAPI) Closing(ctx context.Context) (<-chan struct{}, error) {
	return make(chan struct{}), nil // relies on jsonrpc closing
}


type RPCSystemExtensionAPI struct {}

func (a *RPCSystemExtensionAPI) Discover(ctx context.Context) (*meta_schema.OpenrpcDocument, error) {
	commonPermStruct := &apistruct.CommonStruct{}
	fullStruct := &apistruct.FullNodeStruct{}

	doc := newOpenRPCDocument()

	doc.RegisterReceiverName("common", commonPermStruct)
	doc.RegisterReceiverName("full", fullStruct)

	out, err := doc.Discover()
	if err != nil {
		log.Fatalln(err)
	}
	return out, nil
}

var _ api.Common = &CommonAPI{}


var comments, groupDocs = parseApiASTInfo()

// newOpenRPCDocument returns a Document configured with application-specific logic.
func newOpenRPCDocument() *go_openrpc_reflect.Document {
	d := &go_openrpc_reflect.Document{}

	// Register "Meta" document fields.
	// These include getters for
	// - Servers object
	// - Info object
	// - ExternalDocs object
	//
	// These objects represent server-specific data that cannot be
	// reflected.
	d.WithMeta(&go_openrpc_reflect.MetaT{
		GetServersFn: func() func(listeners []net.Listener) (*meta_schema.Servers, error) {
			return func(listeners []net.Listener) (*meta_schema.Servers, error) {
				return nil, nil
			}
		},
		GetInfoFn: func() (info *meta_schema.InfoObject) {
			info = &meta_schema.InfoObject{}
			title := "Lotus RPC API"
			info.Title = (*meta_schema.InfoObjectProperties)(&title)

			version := build.UserVersion() + "/generated=" + time.Now().Format(time.RFC3339)
			info.Version = (*meta_schema.InfoObjectVersion)(&version)
			return info
		},
		GetExternalDocsFn: func() (exdocs *meta_schema.ExternalDocumentationObject) {
			return nil // FIXME
		},
	})

	// Use a provided Ethereum default configuration as a base.
	appReflector := &go_openrpc_reflect.EthereumReflectorT{}

	// Install overrides for the json schema->type map fn used by the jsonschema reflect package.
	appReflector.FnSchemaTypeMap = func() func(ty reflect.Type) *jsonschema.Type {
		return func(ty reflect.Type) *jsonschema.Type {
			if ty.String() == "uintptr" {
				return &jsonschema.Type{Type: "number", Title: "uintptr-title"}
			}
			return nil
		}
	}

	appReflector.FnIsMethodEligible = func (m reflect.Method) bool {
		for i := 0; i < m.Func.Type().NumOut(); i++ {
			if m.Func.Type().Out(i).Kind() == reflect.Chan {
				return false
			}
		}
		return go_openrpc_reflect.EthereumReflector.IsMethodEligible(m)
	}
	appReflector.FnGetMethodName = func(moduleName string, r reflect.Value, m reflect.Method, funcDecl *ast.FuncDecl) (string, error) {
		if m.Name == "ID" {
			return moduleName + "_ID", nil
		}
		return go_openrpc_reflect.EthereumReflector.GetMethodName(moduleName, r, m, funcDecl)
	}

	appReflector.FnGetMethodSummary = func(r reflect.Value, m reflect.Method, funcDecl *ast.FuncDecl) (string, error) {
		if v, ok := comments[m.Name]; ok {
			return v, nil
		}
		return "", nil // noComment
	}

	// Finally, register the configured reflector to the document.
	d.WithReflector(appReflector)
	return d
}


type Visitor struct {
	Methods map[string]ast.Node
}

func (v *Visitor) Visit(node ast.Node) ast.Visitor {
	st, ok := node.(*ast.TypeSpec)
	if !ok {
		return v
	}

	if st.Name.Name != "FullNode" {
		return nil
	}

	iface := st.Type.(*ast.InterfaceType)
	for _, m := range iface.Methods.List {
		if len(m.Names) > 0 {
			v.Methods[m.Names[0].Name] = m
		}
	}

	return v
}

const noComment = "There are not yet any comments for this method."

func parseApiASTInfo() (map[string]string, map[string]string) { //nolint:golint
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, "./api", nil, parser.AllErrors|parser.ParseComments)
	if err != nil {
		fmt.Println("parse error: ", err)
	}

	ap := pkgs["api"]

	f := ap.Files["api/api_full.go"]

	cmap := ast.NewCommentMap(fset, f, f.Comments)

	v := &Visitor{make(map[string]ast.Node)}
	ast.Walk(v, pkgs["api"])

	groupDocs := make(map[string]string)
	out := make(map[string]string)
	for mn, node := range v.Methods {
		comments := cmap.Filter(node).Comments()
		if len(comments) == 0 {
			out[mn] = noComment
		} else {
			for _, c := range comments {
				if strings.HasPrefix(c.Text(), "MethodGroup:") {
					parts := strings.Split(c.Text(), "\n")
					groupName := strings.TrimSpace(parts[0][12:])
					comment := strings.Join(parts[1:], "\n")
					groupDocs[groupName] = comment

					break
				}
			}

			last := comments[len(comments)-1].Text()
			if !strings.HasPrefix(last, "MethodGroup:") {
				out[mn] = last
			} else {
				out[mn] = noComment
			}
		}
	}
	return out, groupDocs
}
