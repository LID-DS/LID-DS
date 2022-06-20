import os

if __name__ == '__main__':
    

    lid_ds_versions = ['LID-DS-2019', 'LID-DS-2021']
    
    algorithms = ['stide', 'ae', 'mlp', 'som']
    algorithm = algorithms[0]
    
    job_counter = 0
    
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
               "CVE-2017-7529",
               "CVE-2014-0160",
               "CVE-2012-2122",
               "Bruteforce_CWE-307",
               "CVE-2020-23839",
               "CWE-89-SQL-injection",
               "PHP_CWE-434",
               "ZipSlip",
               "CVE-2018-3760",
               "CVE-2020-9484",
               "EPS_CWE-434",
               "CVE-2019-5418",
               "Juice-Shop",
               "CVE-2020-13942",
               "CVE-2017-12635_6"
           ]    
           
        
        for scenario in scenario_names:
            # Construct comman for os - TODO: Muss noch die Argumente weitergeben.
            command = f'sbatch --job-name=exp_{job_counter:03} evaluation.job {version} {scenario} {algorithm}'
            os.system(command)
        
            job_counter += 1
        

        
    # TODO: Die verschiedenen Algorithmen jeweils benutzen.
        