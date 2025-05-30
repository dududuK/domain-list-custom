package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"
)

var (
	dataPath     = flag.String("datapath", filepath.Join("./", "data"), "Path to your custom 'data' directory")
	datName      = flag.String("datname", "geosite.dat", "Name of the generated dat file")
	outputPath   = flag.String("outputpath", "./publish", "Output path to the generated files")
	exportLists  = flag.String("exportlists", "private,microsoft,apple,google,category-games,speedtest,tld-!cn,geolocation-!cn,tld-cn,cn", "Lists to be exported in plaintext format, separated by ',' comma")
	excludeAttrs = flag.String("excludeattrs", "microsoft@ads,apple@ads,google@ads,category-games@ads,speedtest@ads,geolocation-!cn@cn@ads,cn@!cn@ads", "Exclude rules with certain attributes in certain lists, seperated by ',' comma, support multiple attributes in one list. Example: geolocation-!cn@cn@ads,geolocation-cn@!cn")
)

func main() {
	flag.Parse()

	dir := GetDataDir()
	listInfoMap := make(ListInfoMap)

	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if err := listInfoMap.Marshal(path); err != nil {
			return err
		}
		return nil
	}); err != nil {
		fmt.Println("Failed:", err)
		os.Exit(1)
	}

	if err := listInfoMap.FlattenAndGenUniqueDomainList(); err != nil {
		fmt.Println("Failed:", err)
		os.Exit(1)
	}

	// Process and split *excludeRules
	excludeAttrsInFile := make(map[fileName]map[attribute]bool)
	if *excludeAttrs != "" {
		exFilenameAttrSlice := strings.Split(*excludeAttrs, ",")
		for _, exFilenameAttr := range exFilenameAttrSlice {
			exFilenameAttr = strings.TrimSpace(exFilenameAttr)
			exFilenameAttrMap := strings.Split(exFilenameAttr, "@")
			filename := fileName(strings.ToUpper(strings.TrimSpace(exFilenameAttrMap[0])))
			excludeAttrsInFile[filename] = make(map[attribute]bool)
			for _, attr := range exFilenameAttrMap[1:] {
				attr = strings.TrimSpace(attr)
				if len(attr) > 0 {
					excludeAttrsInFile[filename][attribute(attr)] = true
				}
			}
		}
	}

	// Process and split *exportLists
	var exportListsSlice []string
	if *exportLists != "" {
		tempSlice := strings.Split(*exportLists, ",")
		for _, exportList := range tempSlice {
			exportList = strings.TrimSpace(exportList)
			if len(exportList) > 0 {
				exportListsSlice = append(exportListsSlice, exportList)
			}
		}
	}

	// Generate dlc.dat
	if geositeList := listInfoMap.ToProto(excludeAttrsInFile); geositeList != nil {
		protoBytes, err := proto.Marshal(geositeList)
		if err != nil {
			fmt.Println("Failed:", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(*outputPath, 0755); err != nil {
			fmt.Println("Failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*outputPath, *datName), protoBytes, 0644); err != nil {
			fmt.Println("Failed:", err)
			os.Exit(1)
		} else {
			fmt.Printf("%s has been generated successfully in '%s'.\n", *datName, *outputPath)
		}
	}

	// Generate plaintext list files
	if filePlainTextBytesMap, err := listInfoMap.ToPlainText(exportListsSlice); err == nil {
		for filename, plaintextBytes := range filePlainTextBytesMap {
			filename += ".txt"
			if err := os.WriteFile(filepath.Join(*outputPath, filename), plaintextBytes, 0644); err != nil {
				fmt.Println("Failed:", err)
				os.Exit(1)
			} else {
				fmt.Printf("%s has been generated successfully in '%s'.\n", filename, *outputPath)
			}
		}
	} else {
		fmt.Println("Failed:", err)
		os.Exit(1)
	}
}
