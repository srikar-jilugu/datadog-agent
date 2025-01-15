// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package containerd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/efficiency"
	"github.com/DataDog/datadog-agent/pkg/util/trivy"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/mount"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/content"
	containerdevents "github.com/containerd/containerd/events"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"

	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/util"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const imageTopicPrefix = "/images/"

// We cannot get all the information that we need from a single call to
// containerd. This type stores the information that we need to know about the
// images that we have already processed.
//
// Things to take into account:
//
// - Events from containerd only include an image name, and it does not always
// correspond to an image ID. When a delete event arrives it'll contain a name,
// but we won't be able to access the ID because the image is already gone,
// that's why we need to keep the IDs => names relationships.
//
// - An image ID can be referenced by multiple names.
//
// - A name can have multiple formats:
//   - image ID: starts with "sha256:"
//   - repo digest. They contain "@sha256:". Example: gcr.io/datadoghq/agent@sha256:3a19076bfee70900a600b8e3ee2cc30d5101d1d3d2b33654f1a316e596eaa4e0
//   - repo tag. Example: gcr.io/datadoghq/agent:7
type knownImages struct {
	// Store IDs and names in both directions for efficient access.
	idsByName       map[string]string              // map name => ID
	namesByID       map[string]map[string]struct{} // map ID => set of names
	repoTagsByID    map[string]map[string]struct{} // map ID => set of repo tags
	repoDigestsByID map[string]map[string]struct{} // map ID => set of repo digests
}

func newKnownImages() *knownImages {
	return &knownImages{
		idsByName:       make(map[string]string),
		namesByID:       make(map[string]map[string]struct{}),
		repoTagsByID:    make(map[string]map[string]struct{}),
		repoDigestsByID: make(map[string]map[string]struct{}),
	}
}

func (images *knownImages) addReference(imageName string, imageID string) {
	previousIDReferenced, found := images.idsByName[imageName]
	if found && previousIDReferenced != imageID {
		images.deleteReference(imageName, previousIDReferenced)
	}

	images.idsByName[imageName] = imageID

	if images.namesByID[imageID] == nil {
		images.namesByID[imageID] = make(map[string]struct{})
	}
	images.namesByID[imageID][imageName] = struct{}{}

	if isAnImageID(imageName) {
		return
	}

	if isARepoDigest(imageName) {
		if images.repoDigestsByID[imageID] == nil {
			images.repoDigestsByID[imageID] = make(map[string]struct{})
		}
		images.repoDigestsByID[imageID][imageName] = struct{}{}
		return
	}

	// The name is not an image ID or a repo digest, so it has to be a repo tag
	if images.repoTagsByID[imageID] == nil {
		images.repoTagsByID[imageID] = make(map[string]struct{})
	}

	images.repoTagsByID[imageID][imageName] = struct{}{}
}

func (images *knownImages) deleteReference(imageName string, imageID string) {
	delete(images.idsByName, imageName)

	if images.namesByID[imageID] != nil {
		delete(images.namesByID[imageID], imageName)
	}

	if isAnImageID(imageName) {
		return
	}

	if isARepoDigest(imageName) {
		if images.repoDigestsByID[imageID] == nil {
			return
		}
		delete(images.repoDigestsByID[imageID], imageName)
		if len(images.repoDigestsByID[imageID]) == 0 {
			delete(images.repoDigestsByID, imageID)
		}
		return
	}

	// The name is not an image ID or a repo digest, so it has to be a repo tag
	if images.repoTagsByID[imageID] == nil {
		return
	}
	delete(images.repoTagsByID[imageID], imageName)
	if len(images.repoTagsByID[imageID]) == 0 {
		delete(images.repoTagsByID, imageID)
	}
}

func (images *knownImages) getImageID(imageName string) (string, bool) {
	id, found := images.idsByName[imageName]
	return id, found
}

func (images *knownImages) getRepoTags(imageID string) []string {
	var res []string
	for repoTag := range images.repoTagsByID[imageID] {
		res = append(res, repoTag)
	}
	return res
}

func (images *knownImages) getRepoDigests(imageID string) []string {
	var res []string
	for repoDigest := range images.repoDigestsByID[imageID] {
		res = append(res, repoDigest)
	}
	return res
}

// getPreferredName will return a user-friendly image name if it exists, otherwise
// for example the name not including the digest.
func (images *knownImages) getPreferredName(imageID string) string {
	var res = ""
	for ref := range images.namesByID[imageID] {
		if res == "" && isAnImageID(ref) {
			res = ref
		} else if isARepoDigest(ref) {
			res = ref // Prefer the repo digest
			break
		} else {
			res = ref // Then repo tag
		}
	}
	return res
}

// returns any of the existing references for the imageID. Returns empty if the
// ID is not referenced.
func (images *knownImages) getAReference(imageID string) string {
	for ref := range images.namesByID[imageID] {
		return ref
	}

	return ""
}

func isImageTopic(topic string) bool {
	return strings.HasPrefix(topic, imageTopicPrefix)
}

func isAnImageID(imageName string) bool {
	return strings.HasPrefix(imageName, "sha256")
}

func isARepoDigest(imageName string) bool {
	return strings.Contains(imageName, "@sha256:")
}

// pullImageReferences pulls all references from containerd for a given DIGEST
// Note: the DIGEST here is the same as digest (repo digest) field returned from "ctr -n NAMESPACE ls"
// rather than config.digest (imageID), which is the digest of the image config blob.
// In general, 3 reference names are returned for a given DIGEST: repo tag, repo digest, and imageID.
func (c *collector) pullImageReferences(namespace string, img containerd.Image) []string {
	var refs []string
	digest := img.Target().Digest.String()
	if !strings.HasPrefix(digest, "sha256") {
		return refs // not a valid digest
	}

	// Get all references for the imageID
	referenceImages, err := c.containerdClient.ListImagesWithDigest(namespace, digest)
	if err == nil {
		for _, image := range referenceImages {
			imageName := image.Name()
			refs = append(refs, imageName)
		}
	} else {
		log.Debugf("failed to get reference images for image: %s, repo digests will be missing: %v", img.Name(), err)
	}
	return refs
}

func (c *collector) handleImageEvent(ctx context.Context, containerdEvent *containerdevents.Envelope) error {
	switch containerdEvent.Topic {
	case imageCreationTopic:
		event := &events.ImageCreate{}
		if err := proto.Unmarshal(containerdEvent.Event.GetValue(), event); err != nil {
			return fmt.Errorf("error unmarshaling containerd event: %w", err)
		}

		return c.handleImageCreateOrUpdate(ctx, containerdEvent.Namespace, event.Name, nil)

	case imageUpdateTopic:
		event := &events.ImageUpdate{}
		if err := proto.Unmarshal(containerdEvent.Event.GetValue(), event); err != nil {
			return fmt.Errorf("error unmarshaling containerd event: %w", err)
		}

		return c.handleImageCreateOrUpdate(ctx, containerdEvent.Namespace, event.Name, nil)

	case imageDeletionTopic:
		c.handleImagesMut.Lock()

		event := &events.ImageDelete{}
		if err := proto.Unmarshal(containerdEvent.Event.GetValue(), event); err != nil {
			c.handleImagesMut.Unlock()
			return fmt.Errorf("error unmarshaling containerd event: %w", err)
		}

		imageID, found := c.knownImages.getImageID(event.Name)
		if !found {
			c.handleImagesMut.Unlock()
			return nil
		}

		c.knownImages.deleteReference(event.Name, imageID)

		if ref := c.knownImages.getAReference(imageID); ref != "" {
			// Image is still referenced by a different name, so don't delete
			// the image, but we need to update its repo tags and digest tags.
			// Updating workloadmeta entities directly is not thread-safe,
			// that's why we generate an update event here.
			c.handleImagesMut.Unlock()
			return c.handleImageCreateOrUpdate(ctx, containerdEvent.Namespace, ref, nil)
		}

		c.store.Notify([]workloadmeta.CollectorEvent{
			{
				Type:   workloadmeta.EventTypeUnset,
				Source: workloadmeta.SourceRuntime,
				Entity: &workloadmeta.ContainerImageMetadata{
					EntityID: workloadmeta.EntityID{
						Kind: workloadmeta.KindContainerImageMetadata,
						ID:   imageID,
					},
				},
			},
		})

		c.handleImagesMut.Unlock()
		return nil
	default:
		return fmt.Errorf("unknown containerd image event topic %s, ignoring", containerdEvent.Topic)
	}
}

func (c *collector) handleImageCreateOrUpdate(ctx context.Context, namespace string, imageName string, bom *workloadmeta.SBOM) error {
	img, err := c.containerdClient.Image(namespace, imageName)
	if err != nil {
		return fmt.Errorf("error getting image: %w", err)
	}

	return c.notifyEventForImage(ctx, namespace, img, bom)
}

// createOrUpdateImageMetadata: Create image metadata from containerd image and manifest if not already present
// Update image metadata by adding references when existing entity is found
// return nil when it fails to get image manifest
func (c *collector) createOrUpdateImageMetadata(ctx context.Context,
	namespace string,
	img containerd.Image,
	sbom *workloadmeta.SBOM,
	isStartupInit bool) (*workloadmeta.ContainerImageMetadata, error) {
	c.handleImagesMut.Lock()
	defer c.handleImagesMut.Unlock()

	ctxWithNamespace := namespaces.WithNamespace(ctx, namespace)

	// Build initial workloadmeta.ContainerImageMetadata from manifest and image
	manifest, err := images.Manifest(ctxWithNamespace, img.ContentStore(), img.Target(), img.Platform())
	if err != nil {
		return nil, fmt.Errorf("error getting image manifest: %w", err)
	}

	totalSizeBytes := manifest.Config.Size
	for _, layer := range manifest.Layers {
		totalSizeBytes += layer.Size
	}

	wlmImage := workloadmeta.ContainerImageMetadata{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindContainerImageMetadata,
			ID:   manifest.Config.Digest.String(),
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name:      img.Name(),
			Namespace: namespace,
		},
		MediaType: manifest.MediaType,
		SBOM:      sbom,
		SizeBytes: totalSizeBytes,
	}
	// Do not pull references for new image if agent is starting up,
	// because list of all images has already been pulled and will be consolidated in notifyInitialImageEvents
	if !isStartupInit {
		// Only pull all image references if not already present
		if _, found := c.knownImages.getImageID(wlmImage.Name); !found {
			references := c.pullImageReferences(namespace, img)
			for _, ref := range references {
				c.knownImages.addReference(ref, wlmImage.ID)
			}
		}
	}
	// update knownImages with current reference name
	c.knownImages.addReference(wlmImage.Name, wlmImage.ID)

	// Fill image based on manifest and config, we are not failing if this step fails
	// as we can live without layers or labels
	if err := extractFromConfigBlob(ctxWithNamespace, img, manifest, &wlmImage); err != nil {
		log.Infof("failed to get image config for image: %s, layers and labels will be missing: %v", img.Name(), err)
	}

	wlmImage.RepoTags = c.knownImages.getRepoTags(wlmImage.ID)
	wlmImage.RepoDigests = c.knownImages.getRepoDigests(wlmImage.ID)

	// We can get "create" events for images that already exist. That happens
	// when the same image is referenced with different names. For example,
	// datadog/agent:latest and datadog/agent:7 might refer to the same image.
	// Also, in some environments (at least with Kind), pulling an image like
	// datadog/agent:latest creates several events: in one of them the image
	// name is a digest, in other is something with the same format as
	// datadog/agent:7, and sometimes there's a temporary name prefixed with
	// "import-".
	// When that happens, give precedence to the name with repo and tag instead
	// of the name that includes a digest. This is just to show names that are
	// more user-friendly (the digests are already present in other attributes
	// like ID, and repo digest).
	wlmImage.Name = c.knownImages.getPreferredName(wlmImage.ID)
	existingImg, err := c.store.GetImage(wlmImage.ID)
	if err == nil {
		if strings.Contains(wlmImage.Name, "sha256:") && !strings.Contains(existingImg.Name, "sha256:") {
			wlmImage.Name = existingImg.Name
		}
	}

	if wlmImage.SBOM == nil {
		wlmImage.SBOM = &workloadmeta.SBOM{
			Status: workloadmeta.Pending,
		}
	}

	//efficiencyReport, err := c.generateTarEfficiencyReport(ctx, img, &wlmImage, namespace)
	efficiencyReport, err := c.generateMountImageEfficiencyReport(ctx, img, &wlmImage)
	if err != nil && efficiencyReport != nil {
		wlmImage.Efficiency = &workloadmeta.Efficiency{
			Score:               efficiencyReport.Score,
			TotalDiscoveredSize: efficiencyReport.TotalDiscoveredSize,
			TotalMinSize:        efficiencyReport.TotalMinSize,
		}
	}

	// The CycloneDX should contain the RepoTags and RepoDigests but the scanner might
	// not be able to inject them. For example, if we use the scanner from filesystem or
	// if the `imgMeta` object does not contain all the metadata when it is sent.
	// We add them here to make sure they are present.
	wlmImage.SBOM = util.UpdateSBOMRepoMetadata(wlmImage.SBOM, wlmImage.RepoTags, wlmImage.RepoDigests)
	return &wlmImage, nil
}

// generateEfficiencyReport calculates the efficiency of the image and returns the report
func (c *collector) generateEfficiencyReport(ctx context.Context, img containerd.Image, namespace string) (*efficiency.EfficiencyReport, error) {
	// Retrieve the mounts (layers) for the image
	deadline, _ := ctx.Deadline()
	expiration := deadline.Sub(time.Now().Add(30 * time.Second))

	ctxNamespace := namespaces.WithNamespace(ctx, namespace)

	log.Infof("Generating efficiency report for image: %s", img.Name())

	mounts, err := c.containerdClient.Mounts(ctxNamespace, expiration, namespace, img)
	if err != nil {
		log.Errorf("unable to get mounts for image %s: %v", img.Name(), err)
		return nil, fmt.Errorf("unable to get mounts for image %s: %w", img.Name(), err)
	}

	c.mountImageFS(ctxNamespace, mounts)

	//layers := extractLayersFromOverlayFSMounts(mounts)

	// Initialize the new FS Walker for efficiency tracking
	fsWalker := efficiency.NewEfficiencyFSWalker()

	log.Infof("Found %d mounts (layers) for image %s", len(mounts), img.Name())

	// Walk through the layers and track file sizes
	for _, layer := range mounts {
		log.Debugf("Walking layer: %s", layer)
		// Use the walker to process the mounted layer
		err := fsWalker.Walk(layer.Target)
		if err != nil {
			return nil, fmt.Errorf("unable to walk mounted layer %s: %v", layer.Target, err)
		}
	}

	log.Infof("Efficiency report generated for image: %s", img.Name())

	report := efficiency.GenerateEfficiencyReport(fsWalker.EfficiencyMap)
	return report, nil
}

func (c *collector) generateMountImageEfficiencyReport(ctx context.Context, img containerd.Image, imgMeta *workloadmeta.ContainerImageMetadata) (*efficiency.EfficiencyReport, error) {
	// Computing duration of containerd lease
	deadline, _ := ctx.Deadline()
	expiration := deadline.Sub(time.Now().Add(30 * time.Second))

	// Retrieve the mounts (layers) for the image
	log.Infof("Retrieving mounts for image: %s", img.Name())
	mounts, cleanUpSnapshot, err := c.containerdClient.MountLayers(ctx, expiration, imgMeta.Namespace, img)
	if err != nil {
		return nil, fmt.Errorf("unable to mount containerd image, err: %w", err)
	}
	log.Infof("Mounts retrieved for image: %s", img.Name())

	// Ensure cleanup of the snapshot after processing
	defer func() {
		cleanUpContext, cleanUpContextCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := cleanUpSnapshot(cleanUpContext)
		cleanUpContextCancel()
		if err != nil {
			log.Errorf("Unable to clean up mounted image, err: %v", err)
		}
	}()

	imageNum := rand.Int()
	layerPath := fmt.Sprintf("containerd-layer-%d-*", imageNum)
	layers := extractLayersFromOverlayFSMounts(mounts)

	// Process each layer by mounting it to a unique directory
	log.Infof("Creating temporary directories for %d layers and %d mounts", len(layers), len(mounts))
	log.Infof("Layers are: %v", layers)
	for _, layer := range mounts {
		// Generate a unique directory path for each layer
		layerDir, err := os.MkdirTemp("", layerPath) // Ensure the directory exists
		if err != nil {
			return nil, fmt.Errorf("unable to create directory: %w", err)
		}

		log.Infof("Mounting source: %s to target: %s", layer.Source, layerDir)

		// Mount the layer to the unique directory
		_, err = c.mountLayer(ctx, layer, imgMeta.Namespace, img, layerDir)
		if err != nil {
			// If mounting fails, clean up and return an error
			log.Errorf("Error mounting layer: %v", err)
			return nil, fmt.Errorf("unable to mount layer: %w", err)
		}
		// Do not unmount this layer, as you want to keep it for inspection
		// Optionally, log layer information for verification
		log.Infof("Layer mounted at %s for inspection", layerDir)
	}

	return nil, nil
}

/*func (c *collector) generateMountImageEfficiencyReport(ctx context.Context, img containerd.Image, imgMeta *workloadmeta.ContainerImageMetadata) (*efficiency.EfficiencyReport, error) {
	imagePath, err := os.MkdirTemp("", "containerd-layer-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temp dir, err: %w", err)
	}
	defer func() {
		err := os.RemoveAll(imagePath)
		if err != nil {
			log.Errorf("Unable to remove temp dir: %s, err: %v", imagePath, err)
		}
	}()

	// Computing duration of containerd lease
	deadline, _ := ctx.Deadline()
	expiration := deadline.Sub(time.Now().Add(30 * time.Second))

	mounts, cleanUpSnapshot, err := c.containerdClient.MountsWithClean(ctx, expiration, imgMeta.Namespace, img)
	if err != nil {
		return nil, fmt.Errorf("unable to mount containerd image, err: %w", err)
	}

	defer func() {
		cleanUpContext, cleanUpContextCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := cleanUpSnapshot(cleanUpContext)
		cleanUpContextCancel()
		if err != nil {
			log.Errorf("Unable to clean up mounted image, err: %v", err)
		}
	}()

	fsWalker := efficiency.NewEfficiencyFSWalker()

	for _, layer := range mounts {
		// Mount the layer to the temporary directory and get the cleanup function
		cleanUpLayer, err := c.mountLayer(ctx, layer, imgMeta.Namespace, img, imagePath)
		if err != nil {
			// If mounting fails, clean up and return an error
			log.Errorf("Error mounting layer: %v", err)
			return nil, fmt.Errorf("unable to mount layer %s: %w", layer.Source, err)
		}

		err = fsWalker.Walk(imagePath)
		//err = c.processLayerFiles(imagePath)
		if err != nil {
			// If processing fails, unmount and return an error
			log.Errorf("Error processing layer at %s: %v", imagePath, err)
			cleanUpLayer(ctx)
			return nil, fmt.Errorf("unable to process layer %s: %w", layer.Source, err)
		}

		err = cleanUpLayer(ctx)
		if err != nil {
			log.Errorf("Error unmounting layer: %v", err)
			return nil, fmt.Errorf("unable to unmount layer %s: %w", layer.Source, err)
		}
	}

	efficiencyReport := efficiency.GenerateEfficiencyReport(fsWalker.EfficiencyMap)
	log.Infof("Efficiency for image %s: %f", img.Name(), efficiencyReport.Score)

	return nil, nil
}*/

// MountImage mounts an image to a directory
func (c *collector) mountLayer(ctx context.Context, layer mount.Mount, namespace string, img containerd.Image, targetDir string) (func(context.Context) error, error) {
	if err := mount.All([]mount.Mount{layer}, targetDir); err != nil {
		return nil, fmt.Errorf("unable to mount layer on image %s to dir %s, err: %w", img.Name(), targetDir, err)
	}
	return func(ctx context.Context) error {
		ctx = namespaces.WithNamespace(ctx, namespace)
		if err := mount.UnmountAll(targetDir, 0); err != nil {
			return fmt.Errorf("unable to unmount directory: %s for image: %s, err: %w", targetDir, img.Name(), err)
		}
		return nil
	}, nil
}

func (c *collector) processLayerFiles(imagePath string) error {
	// Walk the directory (image filesystem) to track file sizes for efficiency
	var totalSize int64
	var fileCount int

	err := filepath.Walk(imagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("Error walking path %s: %v", path, err)
			return nil
		}

		// If it's a file, calculate its size (for efficiency calculation)
		if !info.IsDir() {
			// Accumulate the total file size
			totalSize += info.Size()
			fileCount++
		}

		return nil
	})

	if err != nil {
		log.Errorf("Error walking mounted directory %s: %v", imagePath, err)
		return fmt.Errorf("unable to walk mounted directory %s: %w", imagePath, err)
	}

	// Log the total size and file count
	log.Infof("Total size of files in mounted directory: %d bytes", totalSize)
	log.Infof("Total number of files: %d", fileCount)

	return nil
}

/*func (c *collector) generateMountImageEfficiencyReport(ctx context.Context, img containerd.Image, imgMeta *workloadmeta.ContainerImageMetadata) (*efficiency.EfficiencyReport, error) {
	imagePath, err := os.MkdirTemp("", "containerd-image-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temp dir, err: %w", err)
	}
	defer func() {
		err := os.RemoveAll(imagePath)
		if err != nil {
			log.Errorf("Unable to remove temp dir: %s, err: %v", imagePath, err)
		}
	}()

	// Computing duration of containerd lease
	deadline, _ := ctx.Deadline()
	expiration := deadline.Sub(time.Now().Add(30 * time.Second))

	mounts, cleanUp, err := c.containerdClient.MountImageWithMounts(ctx, expiration, imgMeta.Namespace, img, imagePath)
	if err != nil {
		return nil, fmt.Errorf("unable to mount containerd image, err: %w", err)
	}

	defer func() {
		cleanUpContext, cleanUpContextCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := cleanUp(cleanUpContext)
		cleanUpContextCancel()
		if err != nil {
			log.Errorf("Unable to clean up mounted image, err: %v", err)
		}
	}()

	layers := extractLayersFromOverlayFSMounts(mounts)
	log.Infof("Found %d mounts (layers) for image %s", len(layers), img.Name())

	files, err := os.ReadDir(imagePath)
	if err != nil {
		log.Errorf("Error reading directory %s: %v", imagePath, err)
		return nil, fmt.Errorf("error reading directory %s: %w", imagePath, err)
	}

	// Log the contents of the directory for inspection
	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}

	log.Infof("Files in mounted directory: %v", fileNames)

	return nil, nil
}*/

func (c *collector) generateTarEfficiencyReport(ctx context.Context, img containerd.Image, imgMeta *workloadmeta.ContainerImageMetadata, namespace string) (*efficiency.EfficiencyReport, error) {
	log.Infof("Generating tar efficiency report for image: %s", img.Name())
	layers, cleanup, err := trivy.GetLayersForEfficiency(ctx, c.containerdClient.RawClient(), imgMeta, img)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, fmt.Errorf("error converting containerd image to fanal image: %w", err)
	}

	// Log the number of layers found
	log.Infof("Found %d layers for image %s. Layers: %v", len(layers), img.Name(), layers)

	// Walk through the layers and track file sizes
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		log.Debugf("Walking layer: %s", layerDigest)

		// Access the uncompressed contents of the layer
		layerContents, err := layer.Uncompressed()
		if err != nil {
			log.Errorf("Unable to read uncompressed layer %s: %v", layerDigest, err)
			return nil, fmt.Errorf("unable to read uncompressed layer %s: %w", layerDigest, err)
		}
		err = processTarball(layerContents)
		if err != nil {
			log.Errorf("Error processing tarball: %v", err)
			return nil, fmt.Errorf("error processing tarball: %w", err)
		}

		// Walk the uncompressed layer contents and track file sizes
	}

	return nil, nil
}

// processTarball processes the contents of the tarball and counts the number of files in it
func processTarball(reader io.Reader) error {
	// Create a tar reader from the io.Reader
	tarReader := tar.NewReader(reader)

	// Initialize file count
	fileCount := 0

	// Walk through the files in the tarball
	for {
		// Get the next file in the tarball
		_, err := tarReader.Next()
		if err == io.EOF {
			break // End of tarball
		}
		if err != nil {
			return fmt.Errorf("failed to read tarball file: %w", err)
		}

		// Log the file name and increment the file count
		fileCount++

		// You can also track file sizes here if needed
		// fsWalker.TrackFileEfficiency(header.Name, header.Size)
	}

	// Log the number of files processed
	log.Infof("Processed %d files in the layer", fileCount)

	return nil
}

func extractLayersFromOverlayFSMounts(mounts []mount.Mount) []string {
	var layers []string
	for _, mount := range mounts {
		for _, opt := range mount.Options {
			for _, prefix := range []string{"upperdir=", "lowerdir="} {
				trimmedOpt := strings.TrimPrefix(opt, prefix)
				if trimmedOpt != opt {
					layers = append(layers, strings.Split(trimmedOpt, ":")...)
				}
			}
		}
	}
	return layers
}

// exportImageToTarball exports the container image to a tarball and returns the file path
func exportImageToTarball(ctx context.Context, img containerd.Image, client *containerd.Client) (string, error) {
	// Create a temporary file to store the tarball
	tmpFile, err := os.CreateTemp("", "containerd-image-*.tar")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Export the image to the tarball
	err = archive.Export(ctx, client.ContentStore(), tmpFile, archive.WithImage(client.ImageService(), img.Name()))
	if err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to export image to tarball: %w", err)
	}

	// Return the path to the tarball file
	return tmpFile.Name(), nil
}

// mountImageFS mounts the image filesystem to a temporary directory and calculates efficiency.
func (c *collector) mountImageFS(ctx context.Context, mounts []mount.Mount) (*efficiency.EfficiencyReport, error) {

	log.Infof("Mounting image filesystem for efficiency calculation")
	targetDir, err := os.MkdirTemp("", "containerd-mount")
	if err != nil {
		log.Errorf("Error creating temporary directory: %v", err)
		return nil, fmt.Errorf("error creating temporary directory: %w", err)
	}

	defer func() {
		err := os.RemoveAll(targetDir)
		if err != nil {
			log.Errorf("Error removing temporary directory: %v", err)
		}
	}()

	err = mount.All(mounts, targetDir)
	if err != nil {
		log.Errorf("Error mounting image filesystems: %v", err)
		return nil, fmt.Errorf("error mounting image filesystems: %w", err)
	}

	log.Infof("Mounted layers at: %s", targetDir)

	// Walk through the mounted directory and log the files
	files, err := os.ReadDir(targetDir)
	if err != nil {
		log.Errorf("Error reading directory %s: %v", targetDir, err)
		return nil, fmt.Errorf("error reading directory %s: %w", targetDir, err)
	}

	// Log the contents of the directory for inspection
	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}

	log.Infof("Files in mounted directory: %v", fileNames)

	return nil, nil

	// Mount the layer's filesystem in read-only mode
	/*err := mount.WithReadonlyTempMount(ctx, mounts, func(root string) error {
		// Log the contents of the directory to inspect it
		log.Infof("Mounting layer at: %s", root)

		// Log the contents of the mounted layer (filesystem)
		files, err := os.ReadDir(root)
		if err != nil {
			return fmt.Errorf("error reading directory %s: %w", root, err)
		}

		// Log the contents of the directory for inspection
		for _, file := range files {
			log.Infof("File: %s", file.Name())
		}
		return nil
		// Walk through the directory and track file sizes for efficiency
		//return fsWalker.Walk(root) // Walk through the mounted layer's files
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting image filesystem: %w", err)
	}

	// Generate and return the efficiency report
	return nil, nil
	//report := efficiency.GenerateEfficiencyReport(fsWalker.EfficiencyMap)
	//return report, nil
	*/
}

func (c *collector) notifyEventForImage(ctx context.Context, namespace string, img containerd.Image, sbom *workloadmeta.SBOM) error {
	wlmImage, err := c.createOrUpdateImageMetadata(ctx, namespace, img, sbom, false)
	if err != nil {
		return err
	}
	c.store.Notify([]workloadmeta.CollectorEvent{
		{
			Type:   workloadmeta.EventTypeSet,
			Source: workloadmeta.SourceRuntime,
			Entity: wlmImage,
		},
	})
	return nil
}

func extractFromConfigBlob(ctx context.Context, img containerd.Image, manifest ocispec.Manifest, outImage *workloadmeta.ContainerImageMetadata) error {
	// First extract platform from Config descriptor
	extractPlatform(manifest.Config.Platform, outImage)

	imageConfigBlob, err := content.ReadBlob(ctx, img.ContentStore(), manifest.Config)
	if err != nil {
		return fmt.Errorf("error getting image config: %w", err)
	}

	var ocispecImage ocispec.Image
	if err = json.Unmarshal(imageConfigBlob, &ocispecImage); err != nil {
		return fmt.Errorf("error while unmarshaling image config: %w", err)
	}

	// If we are able to read config, override with values from config if any
	extractPlatform(&ocispecImage.Platform, outImage)

	outImage.Layers = getLayersWithHistory(ocispecImage, manifest)
	outImage.Labels = getImageLabels(img, ocispecImage)
	return nil
}

func extractPlatform(platform *ocispec.Platform, outImage *workloadmeta.ContainerImageMetadata) {
	if platform == nil {
		return
	}

	if platform.Architecture != "" {
		outImage.Architecture = platform.Architecture
	}

	if platform.OS != "" {
		outImage.OS = platform.OS
	}

	if platform.OSVersion != "" {
		outImage.OSVersion = platform.OSVersion
	}

	if platform.Variant != "" {
		outImage.Variant = platform.Variant
	}
}

func getLayersWithHistory(ocispecImage ocispec.Image, manifest ocispec.Manifest) []workloadmeta.ContainerImageLayer {
	var layers []workloadmeta.ContainerImageLayer

	// If history is present, we use it to associate additional metadata with each layer.
	// Layers marked as "empty" in history are appended before processing the
	// corresponding layer. History is optional in the OCI specification, so if no history is available,
	// the function still processes all layers. Any remaining empty layers in history that
	// do not correspond to a layer are appended at the end.

	historyIndex := 0
	for _, manifestLayer := range manifest.Layers {
		// Append all empty layers encountered before a non-empty layer
		for historyIndex < len(ocispecImage.History) {
			history := ocispecImage.History[historyIndex]
			if history.EmptyLayer {
				layers = append(layers, workloadmeta.ContainerImageLayer{
					History: &history,
				})
				historyIndex++
			} else {
				// Stop at the first non-empty layer
				break
			}
		}

		// Match the non-empty history to this manifest layer, if available
		var history *ocispec.History
		if historyIndex < len(ocispecImage.History) {
			history = &ocispecImage.History[historyIndex]
			historyIndex++
		}

		// Create and append the layer with manifest and matched history
		layer := workloadmeta.ContainerImageLayer{
			MediaType: manifestLayer.MediaType,
			Digest:    manifestLayer.Digest.String(),
			SizeBytes: manifestLayer.Size,
			URLs:      manifestLayer.URLs,
			History:   history,
		}
		layers = append(layers, layer)
	}

	// Append any remaining empty layers after processing all manifest layers
	for historyIndex < len(ocispecImage.History) {
		history := ocispecImage.History[historyIndex]
		if history.EmptyLayer {
			layers = append(layers, workloadmeta.ContainerImageLayer{
				History: &history,
			})
		}
		historyIndex++
	}

	return layers
}

func getImageLabels(img containerd.Image, ocispecImage ocispec.Image) map[string]string {
	// Labels() does not return the labels set in the Dockerfile. They are in
	// the config descriptor.
	// When running on Kubernetes Labels() only returns io.cri-containerd
	// labels.
	labels := map[string]string{}

	for labelName, labelValue := range img.Labels() {
		labels[labelName] = labelValue
	}

	for labelName, labelValue := range ocispecImage.Config.Labels {
		labels[labelName] = labelValue
	}

	return labels
}
