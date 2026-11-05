package extproc

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
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
	native, err := jsonNative(value)
	if err != nil {
		return types.WrapErr(fmt.Errorf("convert CEL value for JSON encoding: %w", err))
	}
	encoded, err := json.Marshal(native)
	if err != nil {
		return types.WrapErr(err)
	}
	return types.String(string(encoded))
}

func jsonNative(value ref.Val) (any, error) {
	if types.IsUnknownOrError(value) {
		return nil, fmt.Errorf("cannot encode CEL error or unknown value: %v", value)
	}
	switch value := value.(type) {
	case traits.Mapper:
		// ConvertToNative(any) can produce map[any]any for dynamic CEL maps,
		// which encoding/json rejects. Traverse collections without guessing types.
		result := map[string]any{}
		iterator := value.Iterator()
		for iterator.HasNext() == types.True {
			key := iterator.Next()
			name, ok := key.(types.String)
			if !ok {
				return nil, fmt.Errorf("JSON object keys must be strings, got %v", key.Type())
			}
			native, err := jsonNative(value.Get(key))
			if err != nil {
				return nil, err
			}
			result[string(name)] = native
		}
		return result, nil
	case traits.Lister:
		result := []any{}
		iterator := value.Iterator()
		for iterator.HasNext() == types.True {
			native, err := jsonNative(iterator.Next())
			if err != nil {
				return nil, err
			}
			result = append(result, native)
		}
		return result, nil
	case types.Null:
		return nil, nil
	default:
		return value.ConvertToNative(reflect.TypeFor[any]())
	}
}
