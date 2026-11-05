package extproc

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/kyverno-authz/pkg/cel/utils"
)

type impl struct{ adapter types.Adapter }

func (i impl) result(action string) ref.Val { return i.adapter.NativeToValue(&Result{Action: action}) }
func (i impl) replaceBody(value ref.Val) ref.Val {
	body, err := utils.ConvertToNative[string](value)
	if err != nil {
		return types.WrapErr(err)
	}
	return i.adapter.NativeToValue(&Result{Action: "continue", Body: body, ReplaceBody: true})
}
func (i impl) respond(value ref.Val) ref.Val {
	status, err := utils.ConvertToNative[int64](value)
	if err != nil {
		return types.WrapErr(err)
	}
	return i.adapter.NativeToValue(&Result{Action: "respond", Status: status})
}
func (i impl) withBody(result, value ref.Val) ref.Val {
	r, err := utils.ConvertToNative[*Result](result)
	if err != nil {
		return types.WrapErr(err)
	}
	body, err := utils.ConvertToNative[string](value)
	if err != nil {
		return types.WrapErr(err)
	}
	r.Body, r.ReplaceBody = body, true
	return i.adapter.NativeToValue(r)
}
func (i impl) withHeader(values ...ref.Val) ref.Val {
	r, err := utils.ConvertToNative[*Result](values[0])
	if err != nil {
		return types.WrapErr(err)
	}
	name, err := utils.ConvertToNative[string](values[1])
	if err != nil {
		return types.WrapErr(err)
	}
	value, err := utils.ConvertToNative[string](values[2])
	if err != nil {
		return types.WrapErr(err)
	}
	r.Headers = append(r.Headers, HeaderMutation{Name: name, Value: value})
	return i.adapter.NativeToValue(r)
}
func (i impl) withoutHeader(result, value ref.Val) ref.Val {
	r, err := utils.ConvertToNative[*Result](result)
	if err != nil {
		return types.WrapErr(err)
	}
	name, err := utils.ConvertToNative[string](value)
	if err != nil {
		return types.WrapErr(err)
	}
	r.Headers = append(r.Headers, HeaderMutation{Name: name, Remove: true})
	return i.adapter.NativeToValue(r)
}
func marshalJSON(value ref.Val) ref.Val {
	native, err := value.ConvertToNative(reflect.TypeFor[any]())
	if err != nil {
		return types.WrapErr(fmt.Errorf("convert CEL value for JSON encoding: %w", err))
	}
	encoded, err := json.Marshal(native)
	if err != nil {
		return types.WrapErr(err)
	}
	return types.String(string(encoded))
}
