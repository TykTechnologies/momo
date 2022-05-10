package converter

import (
	"github.com/kevholditch/gokong"
)

type Service struct {
	ID             string
	Routes         map[string]*Route
	Plugins        []*Plugin
	ServiceRequest gokong.ServiceRequest
	Describe       string
	GetID          string
}

type Route struct {
	ID           string
	Service      string
	Plugins      []*Plugin
	RouteRequest gokong.RouteRequest
	Describe     string
	GetID        string
}

type Plugin struct {
	ID            string
	RouteID       *string
	ServiceID     *string
	PluginRequest gokong.PluginRequest
	Describe      string
	GetID         string
}

type KongOps struct {
	Services map[string]*Service
}

func (o *Service) SetID(id string) {
	o.GetID = id
}

func (o *Service) Create(c *gokong.KongAdminClient) error {
	log.Warn("ServiceID (before check): ", o.GetID)

	if o.GetID != "" {
		return o.Update(c)
	}

	log.Info("[CREATE] ", o.Describe)
	svc, err := c.Services().AddService(&o.ServiceRequest)
	if err != nil {
		return err
	}

	// set ID
	o.GetID = *svc.Id
	log.Warn("ServiceID: ", o.GetID)
	return nil
}

func (o *Service) Update(c *gokong.KongAdminClient) error {
	log.Info("[UPDATE] ", o.Describe)
	svc, err := c.Services().UpdateServiceById(o.GetID, &o.ServiceRequest)
	if err != nil {
		return err
	}

	// set ID
	o.GetID = *svc.Id
	return nil
}

func (o *Route) Create(c *gokong.KongAdminClient) error {
	if o.GetID != "" {
		return o.Update(c)
	}
	log.Info("[CREATE] ", o.Describe)

	log.Debug("route requested for service ID: ", o.RouteRequest.Service.Id)
	rt, err := c.Routes().AddRoute(&o.RouteRequest)
	if err != nil {
		return err
	}

	// set ID
	o.GetID = *rt.Id
	log.Debug("updated route ID: ", o.GetID)
	return nil
}

func (o *Route) Update(c *gokong.KongAdminClient) error {
	log.Info("[UPDATE] ", o.Describe)

	log.Debug("update requested for service ID: ", o.RouteRequest.Service.Id)
	_, err := c.Routes().UpdateRoute(o.GetID, &o.RouteRequest)
	if err != nil {
		return err
	}

	return nil
}

func (o *Plugin) Create(c *gokong.KongAdminClient) error {
	if o.GetID != "" {
		return o.Update(c)
	}
	log.Info("[CREATE] ", o.Describe)

	// Plugin object does not use string pointers so
	// cannot late bind, need indirect
	if o.RouteID != nil {
		o.PluginRequest.RouteId = *o.RouteID
	}
	o.PluginRequest.ServiceId = *o.ServiceID
	log.Debug("plugin requested for route ID: ", o.PluginRequest.RouteId)

	pl, err := c.Plugins().Create(&o.PluginRequest)
	if err != nil {
		return err
	}

	// set ID
	o.GetID = pl.Id
	log.Debug("Plugin: ", o.GetID)
	return nil
}

func (o *Plugin) Update(c *gokong.KongAdminClient) error {
	if o.ID == "acl" {
		log.Warn("[UPDATE] [PLUGIN] detected update on ACL plugin, skipping")
		return nil
	}

	log.Info("[UPDATE] ", o.Describe)

	// Plugin object does not use string pointers so
	// cannot late bind, need indirect
	if o.RouteID != nil {
		o.PluginRequest.RouteId = *o.RouteID
	}
	o.PluginRequest.ServiceId = *o.ServiceID
	log.Debug("update requested for route ID: ", o.PluginRequest.RouteId)

	_, err := c.Plugins().UpdateById(o.GetID, &o.PluginRequest)
	if err != nil {
		return err
	}

	return nil
}
