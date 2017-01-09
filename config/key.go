/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"fmt"
	"strings"

	"github.com/mattn/go-shellwords"
)

func (keyConf *KeyConfig) Name() string {
	return keyConf.name
}

func (keyConf *KeyConfig) GetToolCmd(file string) ([]string, error) {
	if keyConf.Tool == "" {
		return nil, fmt.Errorf("Key \"%s\" does not specify required value 'tool'", keyConf.name)
	} else if keyConf.tool == nil {
		return nil, fmt.Errorf("Tool \"%s\" not defined in configuration (key \"%s\")", keyConf.Tool, keyConf.Name())
	}
	toolConf := keyConf.tool
	if toolConf.Command == "" {
		return nil, fmt.Errorf("Tool \"%s\" does not specify required value 'command'", keyConf.Tool)
	}
	words, err := shellwords.Parse(toolConf.Command)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse tool commandline: %s", err)
	}
	for i, word := range words {
		word = strings.Replace(word, "{file}", file, -1)
		word = strings.Replace(word, "{certificate}", keyConf.Certificate, -1)
		word = strings.Replace(word, "{key}", keyConf.Key, -1)
		words[i] = word
	}
	return words, nil
}