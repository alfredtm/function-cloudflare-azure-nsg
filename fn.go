package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	//"github.com/upbound/provider-aws/apis/s3/v1beta1"
	"github.com/upbound/provider-azure/apis/network/v1beta1"

	"github.com/crossplane/function-sdk-go/errors"
	"github.com/crossplane/function-sdk-go/logging"
	fnv1beta1 "github.com/crossplane/function-sdk-go/proto/v1beta1"
	"github.com/crossplane/function-sdk-go/request"
	"github.com/crossplane/function-sdk-go/resource"
	"github.com/crossplane/function-sdk-go/resource/composed"
	"github.com/crossplane/function-sdk-go/response"
)

// Function returns whatever response you ask it to.
type Function struct {
	fnv1beta1.UnimplementedFunctionRunnerServiceServer

	log logging.Logger
}

// RunFunction observes an XBuckets composite resource (XR). It adds an S3
// bucket to the desired state for every entry in the XR's spec.names array.
func (f *Function) RunFunction(_ context.Context, req *fnv1beta1.RunFunctionRequest) (*fnv1beta1.RunFunctionResponse, error) {
	f.log.Info("Running Function", "tag", req.GetMeta().GetTag())

	// Create a response to the request. This copies the desired state and
	// pipeline context from the request to the response.
	rsp := response.To(req, response.DefaultTTL)

	// Read the observed XR from the request. Most functions use the observed XR
	// to add desired managed resources.
	xr, err := request.GetObservedCompositeResource(req)
	if err != nil {
		// If the function can't read the XR, the request is malformed. This
		// should never happen. The function returns a fatal result. This tells
		// Crossplane to stop running functions and return an error.
		response.Fatal(rsp, errors.Wrapf(err, "cannot get observed composite resource from %T", req))
		return rsp, nil
	}

	// Create an updated logger with useful information about the XR.
	log := f.log.WithValues(
		"xr-version", xr.Resource.GetAPIVersion(),
		"xr-kind", xr.Resource.GetKind(),
		"xr-name", xr.Resource.GetName(),
	)

	// Get the region from the XR. The XR has getter methods like GetString,
	// GetBool, etc. You can use them to get values by their field path.
	nsgName, err := xr.Resource.GetString("spec.nsgName")
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot read spec.region field of %s", xr.Resource.GetKind()))
		return rsp, nil
	}

	desired, err := request.GetDesiredComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get desired resources from %T", req))
		return rsp, nil
	}

	resp, err := http.Get("https://www.cloudflare.com/ips-v4/#")
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "failed to fetch IP addresses from URL"))
		return rsp, nil
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "failed to read response body"))
		return rsp, nil
	}
	// Regexmagic, dont know how this works
	re := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	matches := re.FindAllString(string(body), -1)

	var sourceAddressPrefixes []*string
	for _, match := range matches {
		sourceAddressPrefixes = append(sourceAddressPrefixes, ptr.To(match))
	}
	// Add v1beta1 types (including Bucket) to the composed resource scheme.
	// composed.From uses this to automatically set apiVersion and kind.
	_ = v1beta1.AddToScheme(composed.Scheme)

	s := &v1beta1.SecurityRule{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"corssplane.io/external-name": "cloudflare-ip-allow",
			},
		},
		Spec: v1beta1.SecurityRuleSpec{
			ForProvider: v1beta1.SecurityRuleParameters_2{
				Access:                   ptr.To[string]("Allow"),
				DestinationAddressPrefix: ptr.To[string]("20.100.33.77"),
				Direction:                ptr.To[string]("Inbound"),
				NetworkSecurityGroupName: ptr.To(nsgName),
				Priority:                 ptr.To[float64](100),
				Protocol:                 ptr.To[string]("Tcp"),
				SourceAddressPrefixes:    sourceAddressPrefixes,
				SourcePortRange:          ptr.To("443"),
			},
		},
	}

	// Convert the bucket to the unstructured resource data format the SDK
	// uses to store desired composed resources.
	cd, err := composed.From(s)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot convert %T to %T", s, &composed.Unstructured{}))
		return rsp, nil
	}

	// Add the bucket to the map of desired composed resources. It's
	// important that the function adds the same bucket every time it's
	// called. It's also important that the bucket is added with the same
	// resource.Name every time it's called. The function prefixes the name
	// with "xbuckets-" to avoid collisions with any other composed
	// resources that might be in the desired resources map.
	desired[resource.Name("xbuckets-"+nsgName)] = &resource.DesiredComposed{Resource: cd}

	// Finally, save the updated desired composed resources to the response.
	if err := response.SetDesiredComposedResources(rsp, desired); err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot set desired composed resources in %T", rsp))
		return rsp, nil
	}

	// Log what the function did. This will only appear in the function's pod
	// logs. A function can use response.Normal and response.Warning to emit
	// Kubernetes events associated with the XR it's operating on.
	log.Info("Added desired nsg")

	return rsp, nil
}
