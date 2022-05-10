package converter

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/kevholditch/gokong"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/logger"
)

var (
	moduleName = "momo.drivers.kong.converter"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

type Converter struct {
	Revision map[string]*Service
}

type Deletions struct {
	ServiceIDs []string
	RouteIDs   []string
	PluginIDs  []string
}

func (d *Deletions) DeleteAll(cl *gokong.KongAdminClient) error {
	for _, id := range d.RouteIDs {
		log.Info("[DELETE] [ROUTE] ", id)
		err := cl.Routes().DeleteRoute(id)
		if err != nil {
			return err
		}
	}

	for _, id := range d.PluginIDs {
		log.Info("[DELETE] [PLUGIN] ", id)
		err := cl.Plugins().DeleteById(id)
		if err != nil {
			return err
		}
	}

	for _, id := range d.ServiceIDs {
		log.Info("[DELETE] [SERVICE] ", id)
		err := cl.Services().DeleteServiceById(id)
		if err != nil {
			return err
		}
	}

	return nil
}

func Diff(newRevision, oldRevision map[string]*Service) *Deletions {
	cv := Converter{Revision: newRevision}
	del := &Deletions{}

	del.ServiceIDs = make([]string, 0)
	del.RouteIDs = make([]string, 0)
	del.PluginIDs = make([]string, 0)

	for sn, svc := range oldRevision {
		se := cv.GetExService(sn)
		if se == nil {
			// delete sn
			del.ServiceIDs = append(del.ServiceIDs, svc.GetID)
		}

		for _, pl := range oldRevision[sn].Plugins {
			op := cv.GetExServicePlugin(sn, pl.ID)
			if op == nil {
				// delete pl
				log.Info("plugin disabled: ", pl.ID)
				del.PluginIDs = append(del.PluginIDs, pl.GetID)

			}

		}

		for rn, rt := range oldRevision[sn].Routes {
			or := cv.GetExRoute(sn, rn)
			if or == nil {
				// remove rt
				log.Info("route disabled: ", rt.ID)
				del.RouteIDs = append(del.RouteIDs, rt.GetID)

			}

			for _, rpl := range oldRevision[sn].Routes[rn].Plugins {
				opl := cv.GetExRoutePlugin(sn, rn, rpl.ID)
				if opl == nil {
					// delete rpl
					log.Info("route plugin disabled: ", rpl.ID)
					del.PluginIDs = append(del.PluginIDs, rpl.GetID)
				}
			}
		}
	}

	return del
}

func (c *Converter) GetExService(name string) *Service {
	if c.Revision == nil {
		return nil
	}

	s, ok := c.Revision[name]
	if !ok {
		return nil
	}

	return s
}

func (c *Converter) GetExRoute(service, path string) *Route {
	s := c.GetExService(service)
	if s == nil {
		return nil
	}

	r, ok := s.Routes[path]
	if !ok {
		return nil
	}

	return r
}

func (c *Converter) GetExServicePlugin(service, pluginName string) *Plugin {
	s := c.GetExService(service)
	if s == nil {
		return nil
	}

	for _, pl := range s.Plugins {
		if pl.ID == pluginName {
			return pl
		}
	}

	return nil
}

func (c *Converter) GetExRoutePlugin(service, path, pluginName string) *Plugin {
	r := c.GetExRoute(service, path)
	if r == nil {
		return nil
	}

	for _, pl := range r.Plugins {
		if pl.ID == pluginName {
			return pl
		}
	}

	return nil
}

func (c *Converter) processCORSforService(
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	service *Service,
	route *Route) {
	pr := gokong.PluginRequest{
		ServiceId: service.GetID,
		Name:      "cors",
		Config: map[string]interface{}{
			"origins":            strings.Join(def.CORS.AllowedOrigins, ","),
			"methods":            strings.Join(def.CORS.AllowedMethods, ","),
			"headers":            strings.Join(def.CORS.AllowedHeaders, ","),
			"exposed_headers":    strings.Join(def.CORS.ExposedHeaders, ","),
			"credentials":        def.CORS.AllowCredentials,
			"max_age":            def.CORS.MaxAge,
			"preflight_continue": def.CORS.OptionsPassthrough,
		},
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		ServiceID:     &service.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN] CORS to %s", service.ID),
	}

	if exSvcPl := c.GetExServicePlugin(service.ID, CleanName(pr.Name)); exSvcPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exSvcPl.GetID
	}

	service.Plugins = append(service.Plugins, p)
}

func (c *Converter) processAllowedIPsforService(
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	service *Service,
	route *Route) {
	if len(def.AllowedIPs) == 0 && len(def.BlacklistedIPs) == 0 {
		return
	}

	pr := gokong.PluginRequest{
		ServiceId: service.GetID,
		Name:      "ip-restriction",
		Config: map[string]interface{}{
			"whitelist": strings.Join(def.AllowedIPs, ","),
			"blacklist": strings.Join(def.BlacklistedIPs, ","),
		},
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		ServiceID:     &service.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN] IP list to %s", service.ID),
	}

	if exSvcPl := c.GetExServicePlugin(service.ID, CleanName(pr.Name)); exSvcPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exSvcPl.GetID
	}

	service.Plugins = append(service.Plugins, p)
}

func (c *Converter) processRateLimitForService(
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	service *Service,
	route *Route) {
	if def.GlobalRateLimit.Per <= 0 {
		return
	}

	pr := gokong.PluginRequest{
		ServiceId: service.GetID,
		Name:      "rate-limiting",
		Config:    map[string]interface{}{},
	}

	set := false
	if def.GlobalRateLimit.Per == 1 {
		pr.Config["second"] = def.GlobalRateLimit.Rate
		set = true
	}

	if def.GlobalRateLimit.Per == 60 {
		pr.Config["minute"] = def.GlobalRateLimit.Rate
		set = true
	}

	if def.GlobalRateLimit.Per == (60 * 60) {
		pr.Config["hour"] = def.GlobalRateLimit.Rate
		set = true
	}

	if def.GlobalRateLimit.Per == (60*60)*24 {
		pr.Config["day"] = def.GlobalRateLimit.Rate
		set = true
	}

	if !set {
		ps := def.GlobalRateLimit.Rate / def.GlobalRateLimit.Per
		pr.Config["second"] = ps
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		ServiceID:     &service.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN] global rate limit to %s", service.ID),
	}

	if exSvcPl := c.GetExServicePlugin(service.ID, CleanName(pr.Name)); exSvcPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exSvcPl.GetID
	}

	service.Plugins = append(service.Plugins, p)
}

func (c *Converter) processAuthForService(
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	service *Service,
	route *Route) {
	if def.UseStandardAuth {
		c.processAuthKeyPlugin(route, service, def.Auth.AuthHeaderName, def.Auth.ParamName, def.StripAuthData)
	}

	if def.UseBasicAuth {
		c.processBasicAuthPlugin(route, service, def.StripAuthData)
	}
}

func (c *Converter) ProcessMetaItem(method, path string, cl *gokong.KongAdminClient,
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	service *Service, withAuth bool) *Route {
	route, fnd := service.Routes[path]
	if !fnd {
		// new
		rt := gokong.RouteRequest{
			Methods:      gokong.StringSlice([]string{method}),
			Paths:        gokong.StringSlice([]string{path}),
			PreserveHost: gokong.Bool(def.Proxy.PreserveHostHeader),
			Protocols:    gokong.StringSlice([]string{"http", "https"}),
			Service:      &gokong.RouteServiceObject{Id: service.GetID},
		}

		if def.Domain != "" {
			rt.Hosts = gokong.StringSlice([]string{def.Domain})
		}

		route = &Route{
			ID:           path,
			Service:      service.GetID,
			RouteRequest: rt,
			Plugins:      []*Plugin{},
		}

		service.Routes[path] = route
		route.Describe = fmt.Sprintf("[ROUTE] %s to %s", route.ID, service.ID)

		// Add auth on first sight
		c.processAuthForService(def, ver, service, route)
	}

	// if it exists, then only diff is method
	fndMeth := false
	for _, em := range route.RouteRequest.Methods {
		if em == &method {
			fndMeth = true
		}
	}

	if !fndMeth {
		route.RouteRequest.Methods = append(route.RouteRequest.Methods, gokong.String(method))
	}

	if exRt := c.GetExRoute(service.ID, path); exRt != nil {
		// Set the ID so we know to issue an update
		route.GetID = exRt.GetID
	}

	return route
}

// Blacklist, Whitelist and Ignore arrays
func (c *Converter) processEndpointMetaList(cl *gokong.KongAdminClient,
	def *apidef.APIDefinition,
	ver *apidef.VersionInfo,
	epm []apidef.EndPointMeta,
	pType string, service *Service) {
	auth := true
	if pType == "ignored" {
		auth = false
	}
	for _, pth := range epm {
		for method, cfg := range pth.MethodActions {
			rt := c.ProcessMetaItem(method, pth.Path, cl, def, ver, service, auth)
			if cfg.Action == "reply" {
				// mocks are request termination
				c.processMockPlugin(rt, service, cfg.Code, cfg.Data, cfg.Headers)
			}
		}
	}
}

func CleanName(name string) string {
	nm := strings.ToLower(name)
	nm = strings.Replace(nm, " ", "-", -1)
	nm = strings.Replace(nm, ".", "-", -1)
	nm = strings.Replace(nm, ":", "-", -1)
	return nm
}

func (c *Converter) GetServiceName(defName, versionName string) string {
	vname, err := base64.StdEncoding.DecodeString(versionName)
	if err != nil {
		vname = []byte("decode-failure-default")
	}
	return CleanName(defName + "-" + string(vname))
}

func (c *Converter) processVersion(cl *gokong.KongAdminClient, def *apidef.APIDefinition, ver *apidef.VersionInfo) (*Service, error) {
	svc := &Service{
		ID:      c.GetServiceName(def.Name, ver.Name),
		Routes:  map[string]*Route{},
		Plugins: []*Plugin{},
	}
	r := gokong.ServiceRequest{}

	target := def.Proxy.TargetURL
	if ver.OverrideTarget != "" {
		target = ver.OverrideTarget
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	r.Host = gokong.String(u.Host)
	r.Protocol = gokong.String(u.Scheme)
	r.Name = gokong.String(svc.ID)

	svc.ServiceRequest = r

	svc.Describe = fmt.Sprintf("[SERVICE]: %s", svc.ID)

	// Add ACL on first sight
	c.processACLPlugin(svc)

	c.processRateLimitForService(def, ver, svc, nil)
	c.processAllowedIPsforService(def, ver, svc, nil)

	if def.CORS.Enable {
		c.processCORSforService(def, ver, svc, nil)
	}

	// Process white, black and ignore lists
	c.processEndpointMetaList(cl, def, ver, ver.ExtendedPaths.BlackList, "black", svc)
	c.processEndpointMetaList(cl, def, ver, ver.ExtendedPaths.WhiteList, "white", svc)
	c.processEndpointMetaList(cl, def, ver, ver.ExtendedPaths.Ignored, "ignored", svc)

	for _, pth := range ver.ExtendedPaths.URLRewrite {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.ValidateJSON {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TransformResponse {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.Transform {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TransformHeader {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TransformJQResponse {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TransformJQ {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TrackEndpoints {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.SizeLimit {
		rt := c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
		c.processSizeLimitPlugin(rt, svc, pth.SizeLimit)
	}

	for _, pth := range ver.ExtendedPaths.MethodTransforms {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.HardTimeouts {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.DoNotTrackEndpoints {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.CircuitBreaker {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.TransformResponseHeader {
		c.ProcessMetaItem(pth.Method, pth.Path, cl, def, ver, svc, true)
	}

	for _, pth := range ver.ExtendedPaths.Cached {
		c.ProcessMetaItem("GET", pth, cl, def, ver, svc, true)
		c.ProcessMetaItem("HEAD", pth, cl, def, ver, svc, true)
	}

	if exSvc := c.GetExService(c.GetServiceName(def.Name, ver.Name)); exSvc != nil {
		// Set the ID so we know to issue an update
		svc.GetID = exSvc.GetID
	}

	return svc, nil
}

func (c *Converter) processSizeLimitPlugin(route *Route, svc *Service, size int64) {
	pr := gokong.PluginRequest{
		RouteId: route.GetID,
		Name:    "request-size-limiting",
		Config: map[string]interface{}{
			"allowed_payload_size": size,
		},
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		RouteID:       &route.GetID,
		ServiceID:     &svc.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN]: size-limit to %v on %s", &route.ID, svc.ID),
	}

	if exRtPl := c.GetExRoutePlugin(svc.ID, route.ID, CleanName(p.ID)); exRtPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exRtPl.GetID
	}

	route.Plugins = append(route.Plugins, p)
}

func (c *Converter) processMockPlugin(route *Route, svc *Service, code int, body string, headers map[string]string) {
	pr := gokong.PluginRequest{
		RouteId: route.GetID,
		Name:    "request-termination",
		Config: map[string]interface{}{
			"status_code": code,
			"body":        body,
		},
	}

	ct, ok := headers["content-type"]
	if ok {
		pr.Config["content_type"] = ct
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		RouteID:       &route.GetID,
		ServiceID:     &svc.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN]: request-termination to %v on %s", route.ID, svc.ID),
	}

	if exRtPl := c.GetExRoutePlugin(svc.ID, route.ID, CleanName(p.ID)); exRtPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exRtPl.GetID
	}

	route.Plugins = append(route.Plugins, p)
}

func (c *Converter) processAuthKeyPlugin(route *Route, svc *Service, header, query string, hide bool) {
	if header == "" {
		header = "Authorization"
	}

	if query == "" {
		query = "authorization"
	}

	pr := gokong.PluginRequest{
		ServiceId: svc.GetID,
		RouteId:   route.GetID,
		Name:      "key-auth",
		Config: map[string]interface{}{
			"key_names":        fmt.Sprintf("%s,%s", header, query),
			"hide_credentials": hide,
		},
	}

	p := &Plugin{
		ID:            pr.Name,
		ServiceID:     &svc.GetID,
		RouteID:       &route.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN]: auth key on %v", route.ID),
	}

	if exRtPl := c.GetExRoutePlugin(svc.ID, route.ID, CleanName(p.ID)); exRtPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exRtPl.GetID
	}

	route.Plugins = append(route.Plugins, p)
}

func (c *Converter) processBasicAuthPlugin(route *Route, svc *Service, hide bool) {
	pr := gokong.PluginRequest{
		ServiceId: svc.GetID,
		RouteId:   route.GetID,
		Name:      "basic-auth",
		Config: map[string]interface{}{
			"hide_credentials": hide,
		},
	}

	p := &Plugin{
		ID:            CleanName(pr.Name),
		ServiceID:     &svc.GetID,
		RouteID:       &route.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN]: basic auth to %s service", svc.ID),
	}

	if exRtPl := c.GetExRoutePlugin(svc.ID, route.ID, CleanName(p.ID)); exRtPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exRtPl.GetID
	}

	route.Plugins = append(route.Plugins, p)
}

func (c *Converter) processACLPlugin(svc *Service) {
	pr := gokong.PluginRequest{
		ServiceId: svc.GetID,
		Name:      "acl",
		Config: map[string]interface{}{
			"whitelist": svc.ID,
		},
	}

	p := &Plugin{
		ID:            pr.Name,
		ServiceID:     &svc.GetID,
		PluginRequest: pr,
		Describe:      fmt.Sprintf("[PLUGIN]: ACL on %v", svc.ID),
	}

	if exRtPl := c.GetExServicePlugin(svc.ID, CleanName(p.ID)); exRtPl != nil {
		// Set the ID so we know to issue an update
		p.GetID = exRtPl.GetID
	}

	svc.Plugins = append(svc.Plugins, p)
}

func (c *Converter) CreationOpSetFromTykDef(cl *gokong.KongAdminClient, def *apidef.APIDefinition) map[string]*Service {
	services := map[string]*Service{}
	for _, ver := range def.VersionData.Versions {
		svc, err := c.processVersion(cl, def, &ver)
		if err != nil {
			break
		}

		services[svc.ID] = svc
	}

	return services
}
