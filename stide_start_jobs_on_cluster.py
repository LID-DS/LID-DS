import os

if __name__ == '__main__':
    
    lid_ds_versions = [
        'LID-DS-2019',
        'LID-DS-2021'
        ]

    job_counter = 1
    
    number_of_play_back_alarms = [
        '1',
        '2',
        '3',
        'all'
        ]
 
    back_to_dataset = [
        'training',
        'validation'
        ]
    
    freezing = [
        'True', 
        'False'
        ]
    
    result_path = 'results_stide'
    
    for version in lid_ds_versions:
        if version=="LID-DS-2019":
            scenario_names = [
                "Bruteforce_CWE-307",
                "CVE-2012-2122",
                "CVE-2014-0160",
                "CVE-2017-7529",
                "CVE-2018-3760",
                "CVE-2019-5418",
                "EPS_CWE-434",
                "PHP_CWE-434",
                "SQL_Injection_CWE-89",
                "ZipSlip"
           ]
        else:           
           scenario_names = [
               "Bruteforce_CWE-307",
               "CVE-2012-2122",
               "CVE-2014-0160",
               "CVE-2017-7529",
               "CVE-2017-12635_6",
               "CVE-2018-3760", 
               "CVE-2019-5418",
               "CVE-2020-9484",
               "CVE-2020-13942",
               "CVE-2020-23839",
               "CWE-89-SQL-injection",
               "Juice-Shop",
               "EPS_CWE-434",
               "PHP_CWE-434", 
               "ZipSlip",
           ]    
           
        for play_back_count in number_of_play_back_alarms:
            for back_dataset in back_to_dataset:
                for freeze in freezing:
                    for scenario in scenario_names:
                        # Überspringe sinnlose kombinationen
                        if back_dataset == 'validation' and freeze == 'True':
                            continue
                        
                        command = f'sbatch --job-name=stide{job_counter:03} evaluation_stide.job {version} {scenario} {play_back_count} {result_path} {back_dataset} {freeze}'
                        
                        os.system(command)
                        job_counter += 1
    