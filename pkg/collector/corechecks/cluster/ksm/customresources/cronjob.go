// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package customresources

// This file has most of its logic copied from the KSM cronjob metric family
// generators available at
// https://github.com/kubernetes/kube-state-metrics/blob/release-2.15/internal/store/cronjob.go
// It exists here to provide backwards compatibility with k8s <1.19, as KSM 2.4
// uses API v1 instead of v1beta1: https://github.com/kubernetes/kube-state-metrics/pull/1491

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	basemetrics "k8s.io/component-base/metrics"
	"k8s.io/kube-state-metrics/v2/pkg/customresource"
	"k8s.io/kube-state-metrics/v2/pkg/metric"
	generator "k8s.io/kube-state-metrics/v2/pkg/metric_generator"
)

var (
	descCronJobAnnotationsName     = "kube_cronjob_annotations" //nolint:gosec
	descCronJobAnnotationsHelp     = "Kubernetes annotations converted to Prometheus labels."
	descCronJobLabelsName          = "kube_cronjob_labels"
	descCronJobLabelsHelp          = "Kubernetes labels converted to Prometheus labels."
	descCronJobLabelsDefaultLabels = []string{"namespace", "cronjob"}
)

// NewCronJobV1Beta1Factory returns a new CronJob metric family generator factory.
func NewCronJobV1Beta1Factory(client *apiserver.APIClient) customresource.RegistryFactory {
	return &cronjobv1beta1Factory{
		client: client.Cl,
	}
}

type cronjobv1beta1Factory struct {
	client kubernetes.Interface
}

func (f *cronjobv1beta1Factory) Name() string {
	return "cronjobs"
}

func (f *cronjobv1beta1Factory) CreateClient(_ *rest.Config) (interface{}, error) {
	return f.client, nil
}

func (f *cronjobv1beta1Factory) MetricFamilyGenerators() []generator.FamilyGenerator {
	return []generator.FamilyGenerator{
		*generator.NewFamilyGeneratorWithStability(
			descCronJobAnnotationsName,
			descCronJobAnnotationsHelp,
			metric.Gauge,
			basemetrics.ALPHA,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				annotationKeys, annotationValues := kubeMapToPrometheusLabels("annotation", j.Annotations)
				return &metric.Family{
					Metrics: []*metric.Metric{
						{
							LabelKeys:   annotationKeys,
							LabelValues: annotationValues,
							Value:       1,
						},
					},
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			descCronJobLabelsName,
			descCronJobLabelsHelp,
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				labelKeys, labelValues := kubeMapToPrometheusLabels("label", j.Labels)
				return &metric.Family{
					Metrics: []*metric.Metric{
						{
							LabelKeys:   labelKeys,
							LabelValues: labelValues,
							Value:       1,
						},
					},
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_info",
			"Info about cronjob.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				timeZone := "local"
				if j.Spec.TimeZone != nil {
					timeZone = *j.Spec.TimeZone
				}
				return &metric.Family{
					Metrics: []*metric.Metric{
						{
							LabelKeys:   []string{"schedule", "concurrency_policy", "timezone"},
							LabelValues: []string{j.Spec.Schedule, string(j.Spec.ConcurrencyPolicy), timeZone},
							Value:       1,
						},
					},
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_created",
			"Unix creation timestamp",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}
				if !j.CreationTimestamp.IsZero() {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(j.CreationTimestamp.Unix()),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_status_active",
			"Active holds pointers to currently running jobs.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				return &metric.Family{
					Metrics: []*metric.Metric{
						{
							LabelKeys:   []string{},
							LabelValues: []string{},
							Value:       float64(len(j.Status.Active)),
						},
					},
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_status_last_schedule_time",
			"LastScheduleTime keeps information of when was the last time the job was successfully scheduled.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Status.LastScheduleTime != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(j.Status.LastScheduleTime.Unix()),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_status_last_successful_time",
			"LastSuccessfulTime keeps information of when was the last time the job was completed successfully.",
			metric.Gauge,
			basemetrics.ALPHA,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Status.LastSuccessfulTime != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(j.Status.LastSuccessfulTime.Unix()),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_spec_suspend",
			"Suspend flag tells the controller to suspend subsequent executions.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Spec.Suspend != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       boolFloat64(*j.Spec.Suspend),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_spec_starting_deadline_seconds",
			"Deadline in seconds for starting the job if it misses scheduled time for any reason.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Spec.StartingDeadlineSeconds != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(*j.Spec.StartingDeadlineSeconds),
					})

				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_next_schedule_time",
			"Next time the cronjob should be scheduled. The time after lastScheduleTime, or after the cron job's creation time if it's never been scheduled. Use this to determine if the job is delayed.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				// If the cron job is suspended, don't track the next scheduled time
				nextScheduledTime, err := getNextScheduledTime(j.Spec.Schedule, j.Status.LastScheduleTime, j.CreationTimestamp, j.Spec.TimeZone)
				if err != nil {
					panic(err)
				} else if !*j.Spec.Suspend {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(nextScheduledTime.Unix()),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_metadata_resource_version",
			"Resource version representing a specific version of the cronjob.",
			metric.Gauge,
			basemetrics.STABLE,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				return &metric.Family{
					Metrics: resourceVersionMetric(j.ObjectMeta.ResourceVersion),
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_spec_successful_job_history_limit",
			"Successful job history limit tells the controller how many completed jobs should be preserved.",
			metric.Gauge,
			basemetrics.ALPHA,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Spec.SuccessfulJobsHistoryLimit != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(*j.Spec.SuccessfulJobsHistoryLimit),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
		*generator.NewFamilyGeneratorWithStability(
			"kube_cronjob_spec_failed_job_history_limit",
			"Failed job history limit tells the controller how many failed jobs should be preserved.",
			metric.Gauge,
			basemetrics.ALPHA,
			"",
			wrapCronJobFunc(func(j *batchv1beta1.CronJob) *metric.Family {
				ms := []*metric.Metric{}

				if j.Spec.FailedJobsHistoryLimit != nil {
					ms = append(ms, &metric.Metric{
						LabelKeys:   []string{},
						LabelValues: []string{},
						Value:       float64(*j.Spec.FailedJobsHistoryLimit),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
	}
}

func wrapCronJobFunc(f func(*batchv1beta1.CronJob) *metric.Family) func(interface{}) *metric.Family {
	return func(obj interface{}) *metric.Family {
		cronJob := obj.(*batchv1beta1.CronJob)

		metricFamily := f(cronJob)

		for _, m := range metricFamily.Metrics {
			m.LabelKeys, m.LabelValues = mergeKeyValues(descCronJobLabelsDefaultLabels, []string{cronJob.Namespace, cronJob.Name}, m.LabelKeys, m.LabelValues)
		}

		return metricFamily
	}
}

func (f *cronjobv1beta1Factory) ExpectedType() interface{} {
	return &batchv1beta1.CronJob{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CronJob",
			APIVersion: batchv1beta1.SchemeGroupVersion.String(),
		},
	}
}

func (f *cronjobv1beta1Factory) ListWatch(customResourceClient interface{}, ns string, fieldSelector string) cache.ListerWatcher {
	client := customResourceClient.(kubernetes.Interface)
	ctx := context.Background()
	return &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = fieldSelector
			return client.BatchV1beta1().CronJobs(ns).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = fieldSelector
			return client.BatchV1beta1().CronJobs(ns).Watch(ctx, opts)
		},
	}
}

func getNextScheduledTime(schedule string, lastScheduleTime *metav1.Time, createdTime metav1.Time, timeZone *string) (time.Time, error) {
	if timeZone != nil {
		schedule = fmt.Sprintf("CRON_TZ=%s %s", *timeZone, schedule)
	}

	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		return time.Time{}, fmt.Errorf("Failed to parse cron job schedule '%s': %w", schedule, err)
	}
	if !lastScheduleTime.IsZero() {
		return sched.Next(lastScheduleTime.Time), nil
	}
	if !createdTime.IsZero() {
		return sched.Next(createdTime.Time), nil
	}
	return time.Time{}, errors.New("createdTime and lastScheduleTime are both zero")
}
