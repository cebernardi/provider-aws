/*
Copyright 2020 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificateauthoritypermission

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsacmpca "github.com/aws/aws-sdk-go-v2/service/acmpca"
	awsacmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	"github.com/crossplane/provider-aws/apis/acmpca/v1beta1"
	awsclient "github.com/crossplane/provider-aws/pkg/clients"
	"github.com/crossplane/provider-aws/pkg/clients/acmpca"
	"github.com/crossplane/provider-aws/pkg/clients/acmpca/fake"
)

var (
	// an arbitrary managed resource
	unexpectedItem          resource.Managed
	certificateAuthorityArn = "someauthorityarn"
	nextToken               = "someNextToken"

	errBoom = errors.New("boom")

	sortTags = cmpopts.SortSlices(func(a, b v1beta1.Tag) bool {
		return a.Key > b.Key
	})
)

type args struct {
	acmpca acmpca.CAPermissionClient
	cr     resource.Managed
}

type certificateAuthorityPermissionModifier func(*v1beta1.CertificateAuthorityPermission)

func withConditions(c ...xpv1.Condition) certificateAuthorityPermissionModifier {
	return func(r *v1beta1.CertificateAuthorityPermission) { r.Status.ConditionedStatus.Conditions = c }
}

func withExternalName(name string) func(*v1beta1.CertificateAuthorityPermission) {
	return func(r *v1beta1.CertificateAuthorityPermission) { meta.SetExternalName(r, name) }
}

func withPrincipal(p string) func(*v1beta1.CertificateAuthorityPermission) {
	return func(r *v1beta1.CertificateAuthorityPermission) { r.Spec.ForProvider.Principal = p }
}

func withCertificateAuthorityARN(arn string) func(*v1beta1.CertificateAuthorityPermission) {
	return func(r *v1beta1.CertificateAuthorityPermission) { r.Spec.ForProvider.CertificateAuthorityARN = &arn }
}

func withTags(tagMaps ...map[string]string) func(*v1beta1.CertificateAuthorityPermission) {
	var tagList []v1beta1.Tag
	for _, tagMap := range tagMaps {
		for k, v := range tagMap {
			tagList = append(tagList, v1beta1.Tag{Key: k, Value: v})
		}
	}
	return func(r *v1beta1.CertificateAuthorityPermission) {
		r.Spec.ForProvider.Tags = tagList
	}
}

func withGroupVersionKind() func(*v1beta1.CertificateAuthorityPermission) {
	return func(r *v1beta1.CertificateAuthorityPermission) {
		r.TypeMeta.SetGroupVersionKind(v1beta1.CertificateAuthorityPermissionGroupVersionKind)
	}
}

func certificateAuthorityPermission(m ...certificateAuthorityPermissionModifier) *v1beta1.CertificateAuthorityPermission {
	cr := &v1beta1.CertificateAuthorityPermission{}
	for _, f := range m {
		f(cr)
	}
	return cr
}

func TestObserve(t *testing.T) {
	arn := "aws:arn:cool"
	principal := "excellent"

	type want struct {
		cr     resource.Managed
		result managed.ExternalObservation
		err    error
	}

	cases := map[string]struct {
		args
		want
	}{
		"ValidInput": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockListPermissions: func(ctx context.Context, input *awsacmpca.ListPermissionsInput, opts []func(*awsacmpca.Options)) (*awsacmpca.ListPermissionsOutput, error) {
						return &awsacmpca.ListPermissionsOutput{
							NextToken: aws.String(nextToken),
							Permissions: []awsacmpcatypes.Permission{{
								Actions:                 []awsacmpcatypes.ActionType{awsacmpcatypes.ActionTypeIssueCertificate, awsacmpcatypes.ActionTypeGetCertificate, awsacmpcatypes.ActionTypeListPermissions},
								CertificateAuthorityArn: aws.String(certificateAuthorityArn),
								Principal:               &principal,
							}},
						}, nil
					},
				},
				cr: certificateAuthorityPermission(
					withExternalName(principal+"/"+arn),
					withPrincipal(principal),
					withCertificateAuthorityARN(arn),
				),
			},
			want: want{
				cr: certificateAuthorityPermission(
					withExternalName(principal+"/"+arn),
					withPrincipal(principal),
					withCertificateAuthorityARN(arn),
					withConditions(xpv1.Available()),
				),
				result: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				},
			},
		},
		"InvalidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockListPermissions: func(ctx context.Context, input *awsacmpca.ListPermissionsInput, opts []func(*awsacmpca.Options)) (*awsacmpca.ListPermissionsOutput, error) {
						return nil, errBoom
					},
				},
				cr: certificateAuthorityPermission(withExternalName(principal + "/" + arn)),
			},
			want: want{
				cr:  certificateAuthorityPermission(withExternalName(principal + "/" + arn)),
				err: awsclient.Wrap(errBoom, errGet),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.acmpca,
				kube: &test.MockClient{
					MockUpdate: test.NewMockUpdateFn(nil),
				},
			}
			o, err := e.Observe(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}

			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, o); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	arn := "aws:arn:cool"
	principal := "excellent"
	type want struct {
		cr     resource.Managed
		result managed.ExternalCreation
		err    error
	}

	cases := map[string]struct {
		args
		want
	}{
		"VaildInput": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockCreatePermission: func(ctx context.Context, input *awsacmpca.CreatePermissionInput, opts []func(*awsacmpca.Options)) (*awsacmpca.CreatePermissionOutput, error) {
						return &awsacmpca.CreatePermissionOutput{}, nil
					},
				},
				cr: certificateAuthorityPermission(
					withPrincipal(principal),
					withCertificateAuthorityARN(arn)),
			},
			want: want{
				cr: certificateAuthorityPermission(
					withPrincipal(principal),
					withCertificateAuthorityARN(arn),
					withExternalName(principal+"/"+arn)),
				result: managed.ExternalCreation{},
			},
		},
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockCreatePermission: func(ctx context.Context, input *awsacmpca.CreatePermissionInput, opts []func(*awsacmpca.Options)) (*awsacmpca.CreatePermissionOutput, error) {
						return nil, errBoom
					},
				},
				cr: certificateAuthorityPermission(),
			},
			want: want{
				cr:  certificateAuthorityPermission(),
				err: awsclient.Wrap(errBoom, errCreate),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.acmpca,
				kube: &test.MockClient{
					MockUpdate: test.NewMockUpdateFn(nil),
				},
			}
			o, err := e.Create(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, o); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestDelete(t *testing.T) {

	type want struct {
		cr  resource.Managed
		err error
	}

	cases := map[string]struct {
		args
		want
	}{
		"VaildInput": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockDeletePermission: func(ctx context.Context, input *awsacmpca.DeletePermissionInput, opts []func(*awsacmpca.Options)) (*awsacmpca.DeletePermissionOutput, error) {
						return &awsacmpca.DeletePermissionOutput{}, nil
					},
					MockListPermissions: func(ctx context.Context, input *awsacmpca.ListPermissionsInput, opts []func(*awsacmpca.Options)) (*awsacmpca.ListPermissionsOutput, error) {
						return &awsacmpca.ListPermissionsOutput{
							NextToken:   aws.String(nextToken),
							Permissions: []awsacmpcatypes.Permission{{}},
						}, nil
					},
				},
				cr: certificateAuthorityPermission(),
			},
			want: want{
				cr: certificateAuthorityPermission(),
			},
		},
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockDeletePermission: func(ctx context.Context, input *awsacmpca.DeletePermissionInput, opts []func(*awsacmpca.Options)) (*awsacmpca.DeletePermissionOutput, error) {
						return nil, errBoom
					},
					MockListPermissions: func(ctx context.Context, input *awsacmpca.ListPermissionsInput, opts []func(*awsacmpca.Options)) (*awsacmpca.ListPermissionsOutput, error) {
						return &awsacmpca.ListPermissionsOutput{
							NextToken:   aws.String(nextToken),
							Permissions: []awsacmpcatypes.Permission{{}},
						}, nil
					},
				},
				cr: certificateAuthorityPermission(),
			},
			want: want{
				cr:  certificateAuthorityPermission(),
				err: awsclient.Wrap(errBoom, errDelete),
			},
		},
		"ResourceDoesNotExist": {
			args: args{
				acmpca: &fake.MockCertificateAuthorityPermissionClient{
					MockDeletePermission: func(ctx context.Context, input *awsacmpca.DeletePermissionInput, opts []func(*awsacmpca.Options)) (*awsacmpca.DeletePermissionOutput, error) {
						return nil, &awsacmpcatypes.ResourceNotFoundException{}
					},
					MockListPermissions: func(ctx context.Context, input *awsacmpca.ListPermissionsInput, opts []func(*awsacmpca.Options)) (*awsacmpca.ListPermissionsOutput, error) {
						return &awsacmpca.ListPermissionsOutput{
							NextToken:   aws.String(nextToken),
							Permissions: []awsacmpcatypes.Permission{{}},
						}, nil
					},
				},
				cr: certificateAuthorityPermission(),
			},
			want: want{
				cr:  certificateAuthorityPermission(),
				err: awsclient.Wrap(&awsacmpcatypes.ResourceNotFoundException{}, errDelete),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{client: tc.acmpca}
			err := e.Delete(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	type args struct {
		cr   resource.Managed
		kube client.Client
	}
	type want struct {
		cr  *v1beta1.CertificateAuthorityPermission
		err error
	}

	cases := map[string]struct {
		args
		want
	}{
		"InvalidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				err: errors.New(errUnexpectedObject),
			},
		},
		"Successful": {
			args: args{
				cr:   certificateAuthorityPermission(withTags(map[string]string{"foo": "bar"})),
				kube: &test.MockClient{MockUpdate: test.NewMockUpdateFn(nil)},
			},
			want: want{
				cr: certificateAuthorityPermission(withTags(resource.GetExternalTags(certificateAuthorityPermission()), map[string]string{"foo": "bar"})),
			},
		},
		"Check Tag values": {
			args: args{
				cr:   certificateAuthorityPermission(withTags(map[string]string{"foo": "bar"}), withGroupVersionKind()),
				kube: &test.MockClient{MockUpdate: test.NewMockUpdateFn(nil)},
			},
			want: want{
				cr: certificateAuthorityPermission(withTags(resource.GetExternalTags(certificateAuthorityPermission(withGroupVersionKind())), map[string]string{"foo": "bar"}), withGroupVersionKind()),
			},
		},
		"UpdateFailed": {
			args: args{
				cr:   certificateAuthorityPermission(),
				kube: &test.MockClient{MockUpdate: test.NewMockUpdateFn(errBoom)},
			},
			want: want{
				err: errors.Wrap(errBoom, errKubeUpdateFailed),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &tagger{kube: tc.kube}
			err := e.Initialize(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, sortTags); err == nil && diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}
