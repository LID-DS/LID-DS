/**
 * MongoDB custom function to get the config value for specified config alias
 * Traverses the dependency graph (nodes and links) and the group_by_config graph.
 * When it finds the config alias in the group_by_config graph it returns the value of the corresponding config stored in the db
 *
 * @param {Array} nodes dependency graph nodes
 * @param {Array} links dependency graph links
 * @param {string} algorithm base algorithm
 * @param {Object} group_by_config dictionary of config aliases per algorithm
 * @param {boolean} config_alias the alias of the config value to search
 * @returns {any} the config value for the config alias if a path to the config value exists else undefined
 */
function get_config_value(nodes, links, algorithm, group_by_config, config_alias) {
    if (!(algorithm in group_by_config)) return

    group_by_config = group_by_config[algorithm]
    let algorithm_id = nodes[0].id
    let current_config = nodes[0]
    return get_config(links, [group_by_config], current_config, algorithm_id, config_alias, true)

    function get_config(links, config_group_list, current_config, current_id, config_alias, first) {
        for (let config_group of config_group_list) {
            let target_name = Object.keys(config_group)[0]
            let target = get_target(links, current_config.name, target_name, current_id)

            if (first) {
                target = current_config
            }

            if (!target) return
            let config = config_group[target_name]
            for (let key in config) {
                if (Array.isArray(config[key])) {
                    return get_config(links, config[key], target, target.id, config_alias)
                }
                if (config[key] === config_alias && key in target["config"]) {
                    return target["config"][key]
                }
            }
        }
    }

    function get_target(links, source_name, target_name, source_id) {
        let previous_target_id = source_id
        let found_target = null
        let found_target_id = null
        for (let link of links) {
            if (link.source.name === source_name && link.source.id === previous_target_id) {
                found_target = link.target.name
                found_target_id = link.target.id
                if (found_target === target_name) {
                    return link.target
                }
            }
        }
        return null
    }
}
