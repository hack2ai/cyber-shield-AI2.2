import { getAllAnalyses } from "../analysis/store";


export interface DashboardStats {

    totalScans:number;

    safeUrls:number;

    maliciousUrls:number;

    averageRisk:number;

    threatDistribution:{
        name:string;
        value:number;
    }[];

    recentScans:{
        url:string;
        status:string;
        score:number;
        date:string;
    }[];

}



export function getDashboardStats():DashboardStats{


    const scans =
        getAllAnalyses();



    const totalScans =
        scans.length;



    const safeUrls =
        scans.filter(
            (item:any)=>
            item.status === "safe"
        ).length;



    const maliciousUrls =
        totalScans - safeUrls;



    const averageRisk =
        totalScans === 0
        ?
        0
        :
        Math.round(
            scans.reduce(
                (total:any,item:any)=>
                total + (item.score || 0),
                0
            )
            /
            totalScans
        );



    const threats:any = {};



    scans.forEach((item:any)=>{

        const type =
            item.threatType ||
            item.status ||
            "Unknown";


        threats[type] =
            (threats[type] || 0) + 1;

    });



    const threatDistribution =
        Object.keys(threats)
        .map(key=>({

            name:key,

            value:threats[key]

        }));




    const recentScans =
        scans
        .slice(-10)
        .reverse()
        .map((item:any)=>({

            url:item.url,

            status:item.status,

            score:item.score || 0,

            date:
            item.createdAt ||
            new Date().toISOString()

        }));




    return {

        totalScans,

        safeUrls,

        maliciousUrls,

        averageRisk,

        threatDistribution,

        recentScans

    };


}